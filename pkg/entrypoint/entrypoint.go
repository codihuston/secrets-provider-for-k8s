package entrypoint

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	authnConfigProvider "github.com/cyberark/conjur-authn-k8s-client/pkg/authenticator/config"
	"github.com/cyberark/conjur-authn-k8s-client/pkg/log"
	"github.com/cyberark/conjur-opentelemetry-tracer/pkg/trace"
	"github.com/cyberark/secrets-provider-for-k8s/pkg/log/messages"
	"github.com/cyberark/secrets-provider-for-k8s/pkg/secrets"
	"github.com/cyberark/secrets-provider-for-k8s/pkg/secrets/annotations"
	"github.com/cyberark/secrets-provider-for-k8s/pkg/secrets/clients/conjur"
	secretsConfigProvider "github.com/cyberark/secrets-provider-for-k8s/pkg/secrets/config"
	k8sSecretsStorage "github.com/cyberark/secrets-provider-for-k8s/pkg/secrets/k8s_secrets_storage"
	"github.com/cyberark/secrets-provider-for-k8s/pkg/secrets/pushtofile"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/attribute"
)

const (
	defaultContainerMode       = "init"
	defaultAnnotationsFilePath = "/conjur/podinfo/annotations"
	defaultSecretsBasePath     = "/conjur/secrets"
	defaultTemplatesBasePath   = "/conjur/templates"
	tracerName                 = "secrets-provider"
	tracerService              = "secrets-provider"
	tracerEnvironment          = "production"
	tracerID                   = 1
)

var annotationsMap map[string]string

// CLI configuration variables
var (
	configPath     string
	outputDir      string
	templatesDir   string
	apiKeyFile     string
	spireSocket    string
	useSpire       bool
	apiKey         string
)

var envAnnotationsConversion = map[string]string{
	"CONJUR_AUTHN_LOGIN":     "conjur.org/authn-identity",
	"CONTAINER_MODE":         "conjur.org/container-mode",
	"SECRETS_DESTINATION":    "conjur.org/secrets-destination",
	"K8S_SECRETS":            "conjur.org/k8s-secrets",
	"RETRY_COUNT_LIMIT":      "conjur.org/retry-count-limit",
	"RETRY_INTERVAL_SEC":     "conjur.org/retry-interval-sec",
	"DEBUG":                  "conjur.org/debug-logging",
	"LOG_LEVEL":              "conjur.org/log-level",
	"JAEGER_COLLECTOR_URL":   "conjur.org/jaeger-collector-url",
	"LOG_TRACES":             "conjur.org/log-traces",
	"JWT_TOKEN_PATH":         "conjur.org/jwt-token-path",
	"REMOVE_DELETED_SECRETS": "conjur.org/remove-deleted-secrets-enabled",
}

func StartSecretsProvider() {
	var rootCmd = &cobra.Command{
		Use:   "secrets-provider",
		Short: "Kubernetes Secrets Provider for Conjur",
		Long:  "A Kubernetes Secrets Provider that retrieves secrets from Conjur and stores them in various formats. NOTE: Usage outside of Kubernetes is experimental!",
		Run: func(cmd *cobra.Command, args []string) {
			// Use flag values or defaults
			annotationsFilePath := configPath
			if annotationsFilePath == "" {
				annotationsFilePath = defaultAnnotationsFilePath
			}
			
			secretsBasePath := outputDir
			if secretsBasePath == "" {
				secretsBasePath = defaultSecretsBasePath
			}
			
			templatesBasePath := templatesDir
			if templatesBasePath == "" {
				templatesBasePath = defaultTemplatesBasePath
			}

			// Validate paths
			if err := validatePaths(annotationsFilePath, secretsBasePath, templatesBasePath, apiKeyFile, spireSocket); err != nil {
				fmt.Fprintf(os.Stderr, "Validation error: %v\n", err)
				os.Exit(1)
			}

			exitCode := startSecretsProviderWithDeps(
				annotationsFilePath,
				secretsBasePath,
				templatesBasePath,
				conjur.NewSecretRetriever,
				secrets.NewProviderForType,
				secrets.NewStatusUpdater,
			)
			os.Exit(exitCode)
		},
	}

	// Add flags
	rootCmd.Flags().StringVar(&configPath, "config", "", fmt.Sprintf("Path to annotations file (default: %s)", defaultAnnotationsFilePath))
	rootCmd.Flags().StringVar(&outputDir, "output-dir", "", fmt.Sprintf("Output directory for secrets (default: %s)", defaultSecretsBasePath))
	rootCmd.Flags().StringVar(&templatesDir, "templates-dir", "", fmt.Sprintf("Templates directory (default: %s)", defaultTemplatesBasePath))
	rootCmd.Flags().StringVar(&apiKeyFile, "api-key-file", "", "Path to API key file for Conjur authentication")
	rootCmd.Flags().StringVar(&spireSocket, "spire-socket", "", "Path to SPIRE agent socket")
	rootCmd.Flags().BoolVar(&useSpire, "use-spire", false, "Enable SPIRE JWT authentication")
	rootCmd.Flags().StringVar(&apiKey, "api-key", "", "API key for Conjur authentication")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func validatePaths(annotationsFilePath, secretsBasePath, templatesBasePath, apiKeyFile, spireSocket string) error {
	// Validate config file exists if a custom path is provided
	if configPath != "" {
		if _, err := os.Stat(annotationsFilePath); os.IsNotExist(err) {
			return fmt.Errorf("config file does not exist: %s", annotationsFilePath)
		} else if err != nil {
			return fmt.Errorf("error accessing config file %s: %v", annotationsFilePath, err)
		}
	}

	// Validate that --api-key and --api-key-file are mutually exclusive
	if apiKey != "" && apiKeyFile != "" {
		return fmt.Errorf("--api-key and --api-key-file are mutually exclusive, please specify only one")
	}

	// Validate that CONJUR_AUTHN_API_KEY env var and --api-key-file are mutually exclusive
	if os.Getenv("CONJUR_AUTHN_API_KEY") != "" && apiKeyFile != "" {
		return fmt.Errorf("CONJUR_AUTHN_API_KEY environment variable and --api-key-file are mutually exclusive, please specify only one")
	}

	// Validate that CONJUR_AUTHN_API_KEY env var and --api-key-file are mutually exclusive
	if os.Getenv("CONJUR_AUTHN_API_KEY") != "" && apiKey != "" {
		return fmt.Errorf("CONJUR_AUTHN_API_KEY environment variable and --api-key are mutually exclusive, please specify only one")
	}

	// Validate API key file exists and is readable if provided
	if apiKeyFile != "" {
		if _, err := os.Stat(apiKeyFile); os.IsNotExist(err) {
			return fmt.Errorf("API key file does not exist: %s", apiKeyFile)
		} else if err != nil {
			return fmt.Errorf("error accessing API key file %s: %v", apiKeyFile, err)
		}
		
		// Test if file is readable
		if _, err := os.ReadFile(apiKeyFile); err != nil {
			return fmt.Errorf("API key file is not readable %s: %v", apiKeyFile, err)
		}
	}

	// Validate SPIRE socket exists if provided
	if spireSocket != "" {
		if _, err := os.Stat(spireSocket); os.IsNotExist(err) {
			return fmt.Errorf("SPIRE socket does not exist: %s", spireSocket)
		} else if err != nil {
			return fmt.Errorf("error accessing SPIRE socket %s: %v", spireSocket, err)
		}
	}

	// Validate output directory exists or can be created
	if outputDir != "" {
		if err := ensureDirectoryExists(secretsBasePath); err != nil {
			return fmt.Errorf("output directory validation failed for %s: %v", secretsBasePath, err)
		}
	}

	// Validate templates directory exists or can be created
	if templatesDir != "" {
		if err := ensureDirectoryExists(templatesBasePath); err != nil {
			return fmt.Errorf("templates directory validation failed for %s: %v", templatesBasePath, err)
		}
	}

	return nil
}

func ensureDirectoryExists(dirPath string) error {
	// Check if directory exists
	if stat, err := os.Stat(dirPath); err == nil {
		if !stat.IsDir() {
			return fmt.Errorf("path exists but is not a directory: %s", dirPath)
		}
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("error accessing directory: %v", err)
	}

	// Directory doesn't exist, try to create it
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	return nil
}

func startSecretsProviderWithDeps(
	annotationsFilePath string,
	secretsBasePath string,
	templatesBasePath string,
	retrieverFactory conjur.RetrieverFactory,
	providerFactory secrets.ProviderFactory,
	statusUpdaterFactory secrets.StatusUpdaterFactory,
) (exitCode int) {
	exitCode = 0

	logError := func(errStr string) {
		log.Error(errStr)
		exitCode = 1
	}

	log.Info(messages.CSPFK008I, secrets.FullVersionName)
	log.Info(messages.CSPFK023I, annotationsFilePath)
	log.Info(messages.CSPFK024I, secretsBasePath)
	log.Info(messages.CSPFK025I, templatesBasePath)

	// Create a TracerProvider, Tracer, and top-level (parent) Span
	isConfigFile := configPath != ""
	tracerType, tracerURL := getTracerConfig(annotationsFilePath, isConfigFile)
	ctx, tracer, deferFunc, err := createTracer(tracerType, tracerURL)
	defer deferFunc(ctx)
	if err != nil {
		logError(err.Error())
		return
	}

	// Process Pod Annotations
	log.Info("configPath: '%s', isConfigFile: %t, annotationsFilePath: '%s'", configPath, isConfigFile, annotationsFilePath)
	if err := processAnnotations(ctx, tracer, annotationsFilePath, isConfigFile); err != nil {
		logError(err.Error())
		return
	}

	// Gather K8s authenticator config and create a Conjur secret retriever
	secretRetriever, err := secretRetriever(ctx, tracer, retrieverFactory)
	if err != nil {
		logError(err.Error())
		return
	}

	provideSecrets, secretsConfig, err := secretsProvider(
		ctx,
		tracer,
		secretsBasePath,
		templatesBasePath,
		secretRetriever,
		providerFactory,
	)
	if err != nil {
		logError(err.Error())
		return
	}

	provideSecrets = secrets.RetryableSecretProvider(
		time.Duration(secretsConfig.RetryIntervalSec)*time.Second,
		secretsConfig.RetryCountLimit,
		provideSecrets,
	)

	if err = secrets.RunSecretsProvider(
		secrets.ProviderRefreshConfig{
			Mode:                  getContainerMode(),
			SecretRefreshInterval: secretsConfig.SecretsRefreshInterval,
			// Create a channel to send a quit signal to the periodic secret provider.
			// TODO: Currently, this is just used for testing, but in the future we
			// may want to create a SIGTERM or SIGHUP handler to catch a signal from
			// a user / external entity, and then send an (empty struct) quit signal
			// on this channel to trigger a graceful shut down of the Secrets Provider.
			ProviderQuit: make(chan struct{}),
		},
		provideSecrets,
		statusUpdaterFactory(),
	); err != nil {
		logError(err.Error())
	}
	return
}

func processAnnotations(ctx context.Context, tracer trace.Tracer, annotationsFilePath string, isConfigFile bool) error {
	// Only attempt to populate from annotations if the annotations file exists
	// TODO: Figure out strategy for dealing with explicit annotation file path
	// set by user. In that case we can't just ignore that the file is missing.
	if _, err := os.Stat(annotationsFilePath); err == nil {
		_, span := tracer.Start(ctx, "Process Annotations")
		defer span.End()
		
		var err error
		if isConfigFile {
			// Parse as YAML config file
			log.Info("Processing file as YAML config: %s", annotationsFilePath)
			annotationsMap, err = annotations.NewAnnotationsFromYAMLFile(annotationsFilePath)
		} else {
			// Parse as Kubernetes Downward API annotations file
			log.Info("Processing file as Downward API annotations: %s", annotationsFilePath)
			annotationsMap, err = annotations.NewAnnotationsFromFile(annotationsFilePath)
		}
		
		if err != nil {
			log.Error(err.Error())
			span.RecordErrorAndSetStatus(err)
			return err
		}

		errLogs, infoLogs := secretsConfigProvider.ValidateAnnotations(annotationsMap)
		if err := logErrorsAndInfos(errLogs, infoLogs); err != nil {
			log.Error(messages.CSPFK049E)
			span.RecordErrorAndSetStatus(errors.New(messages.CSPFK049E))
			return err
		}
	}
	return nil
}

func secretRetriever(
	ctx context.Context,
	tracer trace.Tracer,
	retrieverFactory conjur.RetrieverFactory,
) (conjur.RetrieveSecretsFunc, error) {
	// Gather authenticator config
	_, span := tracer.Start(ctx, "Gather authenticator config")
	defer span.End()

	authnConfig, err := authnConfigProvider.NewConfigFromCustomEnv(os.ReadFile, customEnv)
	if err != nil {
		span.RecordErrorAndSetStatus(err)
		log.Error(messages.CSPFK008E)
		return nil, err
	}

	// Initialize a Conjur secret retriever
	secretRetriever, err := retrieverFactory(authnConfig)
	if err != nil {
		log.Error(err.Error())
		return nil, err
	}
	return secretRetriever, nil
}

func secretsProvider(
	ctx context.Context,
	tracer trace.Tracer,
	secretsBasePath string,
	templatesBasePath string,
	secretRetriever conjur.RetrieveSecretsFunc,
	providerFactory secrets.ProviderFactory,
) (secrets.ProviderFunc, *secretsConfigProvider.Config, error) {
	_, span := tracer.Start(ctx, "Create single-use secrets provider")
	defer span.End()

	// Initialize Secrets Provider configuration
	secretsConfig, err := setupSecretsConfig()
	if err != nil {
		log.Error(err.Error())
		span.RecordErrorAndSetStatus(err)
		return nil, nil, err
	}
	providerConfig := &secrets.ProviderConfig{
		CommonProviderConfig: secrets.CommonProviderConfig{
			StoreType:       secretsConfig.StoreType,
			SanitizeEnabled: secretsConfig.SanitizeEnabled,
		},
		K8sProviderConfig: k8sSecretsStorage.K8sProviderConfig{
			PodNamespace:       secretsConfig.PodNamespace,
			RequiredK8sSecrets: secretsConfig.RequiredK8sSecrets,
		},
		P2FProviderConfig: pushtofile.P2FProviderConfig{
			SecretFileBasePath:   secretsBasePath,
			TemplateFileBasePath: templatesBasePath,
			AnnotationsMap:       annotationsMap,
		},
	}

	// Tag the span with the secrets provider mode
	span.SetAttributes(attribute.String("store_type", secretsConfig.StoreType))

	// Create a secrets provider
	provideSecrets, errs := providerFactory(ctx,
		secretRetriever, *providerConfig)
	if err := logErrorsAndInfos(errs, nil); err != nil {
		log.Error(messages.CSPFK053E)
		span.RecordErrorAndSetStatus(errors.New(messages.CSPFK053E))
		return nil, nil, err
	}

	return provideSecrets, secretsConfig, nil
}

func customEnv(key string) string {
	// Handle special case for API key file
	if key == "CONJUR_AUTHN_API_KEY_FILE" {
		// Check environment variable first
		if envValue := os.Getenv(key); envValue != "" {
			log.Info(messages.CSPFK014I, key, "environment")
			return envValue
		}
		// Fall back to flag if environment variable is not set
		if apiKeyFile != "" {
			// Warn if both API key methods are provided via flags (validation should have caught this)
			if apiKey != "" {
				log.Warn("Both --api-key and --api-key-file flags provided, using --api-key-file")
			}
			log.Info(messages.CSPFK014I, key, "api-key-file flag")
			return apiKeyFile
		}
	}
	
	// Handle special case for API key
	if key == "CONJUR_AUTHN_API_KEY" {
		// Check environment variable first
		if envValue := os.Getenv(key); envValue != "" {
			log.Info(messages.CSPFK014I, key, "environment")
			return envValue
		}
		// Fall back to flag if environment variable is not set
		// Only use --api-key flag if --api-key-file is not set (mutual exclusivity)
		if apiKey != "" && apiKeyFile == "" {
			log.Info(messages.CSPFK014I, key, "api-key flag")
			return apiKey
		}
	}
	
	// Handle special case for SPIRE socket
	if key == "SPIRE_AGENT_SOCKET_PATH" {
		// Check environment variable first
		if envValue := os.Getenv(key); envValue != "" {
			log.Info(messages.CSPFK014I, key, "environment")
			return envValue
		}
		// Fall back to flag if environment variable is not set
		if spireSocket != "" {
			log.Info(messages.CSPFK014I, key, "spire-socket flag")
			return spireSocket
		}
	}
	
	// Handle special case for SPIRE JWT authentication
	if key == "ENABLE_SPIRE_JWT_AUTHN" {
		// Check environment variable first
		if envValue := os.Getenv(key); envValue != "" {
			// Only return "true" if the env value is exactly "true", otherwise "false"
			if envValue == "true" {
				log.Info(messages.CSPFK014I, key, "environment")
				return "true"
			} else {
				log.Info(messages.CSPFK014I, key, "environment")
				return "false"
			}
		}
		// Fall back to flag if environment variable is not set
		if useSpire {
			log.Info(messages.CSPFK014I, key, "use-spire flag")
			return "true"
		} else {
			log.Info(messages.CSPFK014I, key, "use-spire flag")
			return "false"
		}
	}
	
	if annotation, ok := envAnnotationsConversion[key]; ok {
		if value := annotationsMap[annotation]; value != "" {
			log.Info(messages.CSPFK014I, key, fmt.Sprintf("annotation %s", annotation))
			return value
		}

		if value := os.Getenv(key); value == "" && key == "CONTAINER_MODE" {
			log.Info(messages.CSPFK014I, key, "default")
			return defaultContainerMode
		}

		log.Info(messages.CSPFK014I, key, "environment")
	}

	return os.Getenv(key)
}

func setupSecretsConfig() (*secretsConfigProvider.Config, error) {
	secretsProviderSettings := secretsConfigProvider.GatherSecretsProviderSettings(annotationsMap)

	errLogs, infoLogs := secretsConfigProvider.ValidateSecretsProviderSettings(secretsProviderSettings)
	if err := logErrorsAndInfos(errLogs, infoLogs); err != nil {
		log.Error(messages.CSPFK015E)
		return nil, err
	}

	return secretsConfigProvider.NewConfig(secretsProviderSettings), nil
}

func logErrorsAndInfos(errLogs []error, infoLogs []error) error {
	for _, err := range infoLogs {
		log.Info(err.Error())
	}
	if len(errLogs) > 0 {
		for _, err := range errLogs {
			log.Error(err.Error())
		}
		return errors.New("fatal errors occurred, check Secrets Provider logs")
	}
	return nil
}

func getContainerMode() string {
	containerMode := "init"
	if mode, exists := annotationsMap[secretsConfigProvider.ContainerModeKey]; exists {
		containerMode = mode
	} else if mode = os.Getenv("CONTAINER_MODE"); mode == "sidecar" || mode == "application" {
		containerMode = mode
	}
	return containerMode
}
