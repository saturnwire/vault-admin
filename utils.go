package main

import (
	"encoding/json"
	// "gopkg.in/yaml.v2"
	"errors"
	"fmt"
	"io/ioutil"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
)

var (
	ErrNotExist = errors.New("secret does not exist")
)

func getJsonFile(path string) (bool, string) {
	if checkExt(path, ".json") {
		content, err := ioutil.ReadFile(path)
		if err != nil {
			log.Fatal(err)
		}

		if !isJSON(string(content)) {
			log.Fatal("File is not valid JSON: ", path)
		}

		return true, string(content)
	} else {
		log.Warn("File has wrong extension.  Will not be processed: ", path)
		return false, ""
	}
}

func getSecretArray(path string) (map[string]string, error) {

	secretArray := make(map[string]string)

	kvVersion, err := kvVersionByPath(path)
	if err != nil {
		return nil, err
	}

	if kvVersion == 2 {
		pathParts := strings.Split(path, "/")
		pathParts = SliceInsert(pathParts, 1, "data")
		path = strings.Join(pathParts, "/")
	}

	// Read secrets from Vault for substitution
	secret, err := Vault.Read(path)
	if err != nil {
		return nil, err
	}

	if secret != nil {

		if len(secret.Warnings) > 0 {
			for _, v := range secret.Warnings {
				log.Warnf("Read secret warning: %s", v)
			}
		}

		for k, v := range secret.Data {

			switch value := v.(type) {
			// v1
			case string:
				secretArray[k] = value
			// v2
			case map[string]interface{}:
				if k == "data" {
					for x, y := range value {
						if data, ok := y.(string); ok {
							secretArray[x] = data
						}
					}
				}
			default:
				log.Fatal("Issue parsing Vault secret [" + path + "]")
			}
		}
	} else {
		return nil, ErrNotExist
	}

	return secretArray, nil
}

func SliceInsert[V any](a []V, index int, value V) []V {
	if len(a) == index { // nil or empty slice or after last element
		return append(a, value)
	}
	a = append(a[:index+1], a[index:]...) // index < len(a)
	a[index] = value
	return a
}

// GetSecretListKeyInfo takes a path and performs a LIST operation on it
// If available, returns a map of key_info
// If second parameter, v, is passed, info is unmarshalled
func GetSecretListKeyInfo(path string, v interface{}) (map[string]interface{}, error) {

	secretMap := make(map[string]interface{})

	secret, err := Vault.List(path)
	if err != nil {
		return nil, err
	}

	if secret != nil {
		if _, ok := secret.Data["key_info"]; ok {
			switch value := secret.Data["key_info"].(type) {
			case map[string]interface{}:
				if v != nil {
					jsondata, err := json.Marshal(value)
					if err != nil {
						return nil, err
					}
					if err := json.Unmarshal(jsondata, v); err != nil {
						return nil, err
					}
				} else {
					return value, nil
				}
			default:
				return nil, errors.New("Secret list failed on [" + path + "], expected map[string]interface {} but got " + fmt.Sprintf("%T", value))
			}
		} else {
			return nil, errors.New("Secret list failed on [" + path + "], no \"key_info\" present")
		}
	} else {
		return nil, nil
	}

	return secretMap, nil
}

func getSecretList(path string) SecretList {

	var secretList SecretList

	// Read secrets from Vault for substitution
	secret, err := Vault.List(path)
	if err != nil {
		log.Fatal(err)
	}

	if secret != nil {
		for _, v := range secret.Data {
			switch value := v.(type) {
			case []interface{}:
				for _, k := range value {
					switch key := k.(type) {
					case string:
						secretList = append(secretList, string(key))
					default:
						log.Fatal("Issue parsing Vault secret list [" + path + "] [error 001]")
					}
				}
			default:
				log.Fatal("Issue parsing Vault secret list [" + path + "] [error 002]")
			}
		}
	} else {
		return nil
	}

	return secretList
}

func performSubstitutions(content *string, secretPath string) error {

	var secrets map[string]string
	fullSecretPath := Spec.VaultSecretBasePath + secretPath
	secrets, err := getSecretArray(fullSecretPath)

	if err != nil {
		if errors.Is(err, ErrNotExist) {
			secrets = make(map[string]string)
		} else {
			return err
		}
	}
	for k, v := range secrets {
		*content = strings.Replace(*content, "%{"+k+"}%", v, -1)
	}

	// Ensure all the variables were substituted
	re := regexp.MustCompile(`(%\{[a-zA-Z0-9_]+\}%)`)
	matches := re.FindAllStringSubmatch(*content, -1)
	if len(matches) > 0 {
		var matchArray []string
		for _, match := range matches {
			matchArray = append(matchArray, match[0])
		}
		return fmt.Errorf("The following substitutions were detected but not found in Vault path ["+fullSecretPath+"]: %v", strings.Join(matchArray, ", "))
	}

	return nil
}

// Determines the version of a KV store by path
// Returns version of the kv store or
// returns 0 with error if error
func kvVersionByPath(path string) (int, error) {

	mounts, err := VaultSys.ListMounts()
	if err != nil {
		log.Fatalf("Failed to list mounts: %v", err)
	}

	pathParts := strings.Split(path, "/")
	if mount, ok := mounts[pathParts[0]+"/"]; ok {
		if mount.Type != "kv" {
			return 0, fmt.Errorf("cannot determine kv version; mountpoint '%s' is not a kv secret backend", pathParts[0]+"/")
		} else if mount.Options == nil {
			return 1, nil
		} else if mount.Options["version"] == "2" {
			return 2, nil
		} else {
			return 1, nil
		}
	} else {
		return 0, fmt.Errorf("cannot determine kv version; mountpoint '%s' not found", pathParts[0]+"/")
	}
}

func checkExt(filename string, ext string) bool {
	return filepath.Ext(filename) == ext
}

func isJSON(s string) bool {
	var x map[string]interface{}
	return json.Unmarshal([]byte(s), &x) == nil
}

func isYAML(s string) (bool, error) {
	// var x map[string]interface{}
	// err := yaml.Unmarshal([]byte(s), &x)
	// return err == nil, err
	return false, errors.New("YAML is not yet supported")
}

func askForConfirmation(msg string, max int) bool {

	if max > 0 {
		var response string
		fmt.Print(msg)
		_, err := fmt.Scanln(&response)
		if err != nil {
			log.Debug(err)
			return askForConfirmation(msg, max-1)
		}

		if strings.ToLower(string(response[0])) == "y" {
			return true
		} else if strings.ToLower(string(response[0])) == "n" {
			return false
		} else {
			fmt.Println("Invalid response.")
			return askForConfirmation(msg, max-1)
		}
	}

	log.Warning("Max number of invalid confirmations reached, exiting with 'n' response")
	return false
}

// structToMap takes in an arbitrary interface and converts it into a map[string]interface{}
// using the json/yaml tags
// This is the format that Vault uses for writing data
func structToMap(item interface{}) map[string]interface{} {
	jsonData, err := json.Marshal(&item)
	if err != nil {
		log.Fatalf("Unable to marshall struct: %v", err)
	}

	var mm map[string]interface{}
	err = json.Unmarshal(jsonData, &mm)
	if err != nil {
		log.Fatalf("Unable to unmarshall struct: %v", err)
	}

	return mm
}

func processDirectoryRaw(dirPath string) map[string][]byte {

	results := make(map[string][]byte)

	files, err := ioutil.ReadDir(dirPath)
	if err != nil {
		log.Warnf("Error reading configuration directory [%s]: %v", dirPath, err)
	}

	for _, file := range files {
		filePath := path.Join(dirPath, file.Name())
		fileExtension := filepath.Ext(file.Name())
		if fileExtension == ".json" || fileExtension == ".yaml" {
			fileContent, err := ioutil.ReadFile(filePath)
			if err != nil {
				log.Fatalf("Error reading file [%s]: %v", filePath, err)
			}

			fileStringContent := string(fileContent)
			if fileExtension == ".json" && !isJSON(fileStringContent) {
				log.Fatalf("Configuration file [%s] is not valid JSON", filePath)
			}
			if fileExtension == ".yaml" {
				_, err := isYAML(fileStringContent)
				if err != nil {
					log.Fatalf("Configuration file [%s] is not valid: %v", filePath, err)
				}
			}

			itemName := strings.TrimSuffix(file.Name(), filepath.Ext(file.Name()))
			results[itemName] = fileContent

		} else {
			log.Warnf("Configuration file [%s] does not have valid json/yaml extension and will not be processed", filePath)
		}
	}

	return results
}
