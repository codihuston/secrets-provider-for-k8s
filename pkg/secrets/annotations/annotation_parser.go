package annotations

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/cyberark/conjur-authn-k8s-client/pkg/log"
	"gopkg.in/yaml.v3"

	"github.com/cyberark/secrets-provider-for-k8s/pkg/log/messages"
)

// fileOpener is a function type that captures dependency injection for
// filesystem operations. It returns an instantiation of the 'io.ReadCloser'
// interface, which incorporates the only two filesystem operations that we
// need for parsing an annotations file:
//   - File closer
//   - IO reader
type fileOpener func(name string, flag int, perm os.FileMode) (io.ReadCloser, error)

// osFileOpener is a 'fileOpener' that uses standard OS.
func osFileOpener(name string, flag int, perm os.FileMode) (io.ReadCloser, error) {
	return os.OpenFile(name, flag, perm)
}

// NewAnnotationsFromFile reads and parses an annotations file that has been
// created by Kubernetes via the Downward API, based on Pod annotations that
// are defined in a deployment manifest.
func NewAnnotationsFromFile(path string) (map[string]string, error) {
	// Use standard OS
	res, err := newAnnotationsFromFile(osFileOpener, path)
	if err != nil {
		return nil, fmt.Errorf(messages.CSPFK041E, path, err)
	}

	return res, nil
}

// NewAnnotationsFromYAMLFile reads and parses a YAML configuration file,
// converting it to the same string-to-string map format that Kubernetes
// Downward API annotations produce.
func NewAnnotationsFromYAMLFile(path string) (map[string]string, error) {
	// Use standard OS
	res, err := newAnnotationsFromYAMLFile(osFileOpener, path)
	if err != nil {
		return nil, fmt.Errorf(messages.CSPFK041E, path, err)
	}

	return res, nil
}

// newAnnotationsFromFile performs the work of NewAnnotationsFromFile(), and
// provides a function entrypoint that allows filesystem mocking for test
// purposes.
func newAnnotationsFromFile(fo fileOpener, path string) (map[string]string, error) {
	annotationsFile, err := fo(path, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return nil, err
	}
	defer annotationsFile.Close()
	return newAnnotationsFromReader(annotationsFile)
}

// newAnnotationsFromYAMLFile performs the work of NewAnnotationsFromYAMLFile(), and
// provides a function entrypoint that allows filesystem mocking for test
// purposes.
func newAnnotationsFromYAMLFile(fo fileOpener, path string) (map[string]string, error) {
	yamlFile, err := fo(path, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return nil, err
	}
	defer yamlFile.Close()
	return newAnnotationsFromYAMLReader(yamlFile)
}

// newAnnotationsFromReader parses an input stream representing an annotations file that
// had been created by Kubernetes via the Downward API, returning a
// string-to-string map of annotations key-value pairs.
//
// List and multi-line annotations are formatted as a single string in the
// annotations file, and this format persists into the map returned by this
// function. For example, the following annotation:
//   conjur.org/conjur-secrets.cache: |
//     - url
//     - admin-password: password
//     - admin-username: username
// Is stored in the annotations file as:
//   conjur.org/conjur-secrets.cache="- url\n- admin-password: password\n- admin-username: username\n"
func newAnnotationsFromReader(annotationsFile io.Reader) (map[string]string, error) {
	var lines []string
	scanner := bufio.NewScanner(annotationsFile)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	// Log the annotations file content for debugging
	log.Info("Annotations file contents (expecting Downward API format):")
	for i, line := range lines {
		log.Info("Line %d: %s", i+1, line)
	}

	annotationsMap := make(map[string]string)
	for lineNumber, line := range lines {
		keyValuePair := strings.SplitN(line, "=", 2)
		if len(keyValuePair) == 1 {
			return nil, log.RecordedError(messages.CSPFK045E, lineNumber+1)
		}

		key := keyValuePair[0]
		value, err := strconv.Unquote(keyValuePair[1])
		if err != nil {
			return nil, log.RecordedError(messages.CSPFK045E, lineNumber+1)
		}

		annotationsMap[key] = value
	}

	return annotationsMap, nil
}

// newAnnotationsFromYAMLReader parses a YAML configuration file and converts
// it to the same string-to-string map format that Kubernetes Downward API
// annotations produce. This allows using YAML config files with the same
// structure as Pod annotations.
func newAnnotationsFromYAMLReader(yamlFile io.Reader) (map[string]string, error) {
	// Read the entire YAML content
	yamlContent, err := io.ReadAll(yamlFile)
	if err != nil {
		return nil, log.RecordedError(messages.CSPFK041E, "failed to read YAML file", err)
	}

	// Log the YAML content for debugging
	log.Info("YAML config file contents:\n%s", string(yamlContent))

	// Parse YAML into a generic map
	var yamlData map[string]interface{}
	err = yaml.Unmarshal(yamlContent, &yamlData)
	if err != nil {
		return nil, log.RecordedError(messages.CSPFK041E, "failed to parse YAML", err)
	}

	// Convert to string-to-string map, mimicking Downward API format
	annotationsMap := make(map[string]string)
	for key, value := range yamlData {
		// Convert value to string, handling different types
		stringValue, err := convertYAMLValueToString(value)
		if err != nil {
			return nil, log.RecordedError(messages.CSPFK041E, fmt.Sprintf("failed to convert value for key %s", key), err)
		}
		annotationsMap[key] = stringValue
	}

	return annotationsMap, nil
}

// convertYAMLValueToString converts a YAML value to string format that matches
// how Kubernetes Downward API formats annotation values
func convertYAMLValueToString(value interface{}) (string, error) {
	switch v := value.(type) {
	case string:
		return v, nil
	case []interface{}:
		// Convert array to multi-line string format like Downward API
		var lines []string
		for _, item := range v {
			itemStr, err := convertYAMLValueToString(item)
			if err != nil {
				return "", err
			}
			lines = append(lines, "- "+itemStr)
		}
		return strings.Join(lines, "\n") + "\n", nil
	case map[string]interface{}:
		// Convert nested map to YAML-like string format
		yamlBytes, err := yaml.Marshal(v)
		if err != nil {
			return "", err
		}
		return string(yamlBytes), nil
	default:
		// Convert other types (int, bool, etc.) to string
		return fmt.Sprintf("%v", v), nil
	}
}
