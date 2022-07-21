package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path"
	"strconv"
	"text/template"

	log "github.com/sirupsen/logrus"
)

type SecretsEngineGCP struct {
	RootConfig               GcpRootConfig              `json:"root_config"`
	OverwriteRootCredentials bool                       `json:"overwrite_root_config"`
	ConfigLease              GcpConfigLease             `json:"config_lease"`
	RoleSets                 map[string]gcpRoleSetEntry `json:"rolesets"`
}

type GcpRootConfig struct {
	Credentials GcpCredentials `json:"credentials"`
}

// vault expects credentials to be a json string
func (r GcpRootConfig) MarshalJSON() ([]byte, error) {
	type Alias GcpRootConfig

	credentials, err := json.Marshal(r.Credentials)
	if err != nil {
		return []byte{}, err
	}

	return json.Marshal(&struct {
		Credentials string `json:"credentials"`
		Alias
	}{
		Credentials: string(credentials),
		Alias:       (Alias)(r),
	})
}

type GcpCredentials struct {
	Type                    string `json:"type"`
	ProjectId               string `json:"project_id"`
	PrivateKeyId            string `json:"private_key_id"`
	PrivateKey              string `json:"private_key"`
	ClientEmail             string `json:"client_email"`
	ClientId                string `json:"client_id"`
	AuthUri                 string `json:"auth_uri"`
	TokenUri                string `json:"token_uri"`
	AuthProviderX509CertUrl string `json:"auth_provider_x509_cert_url"`
	ClientX509CertUrl       string `json:"client_x509_cert_url"`
}

type GcpConfigLease struct {
	TTL    string `json:"ttl"`
	MaxTTL string `json:"max_ttl"`
}

type gcpRoleSetEntry struct {
	Project    string       `json:"project"`
	SecretType string       `json:"secret_type"`
	Bindings   []gcpBinding `json:"bindings"`
}

type gcpBinding struct {
	Resource string   `json:"resource"`
	Roles    []string `json:"roles"`
}

func (r gcpRoleSetEntry) BindingsAsHCL() (string, error) {
	templateString := `{{- range .Bindings }}
resource "{{ .Resource }}" {
  roles = [{{- range $index, $element := .Roles }}{{- if $index }},{{ end}}"{{.}}"{{- end }}]
}
{{- end }}`
	parsedTemplate, err := template.New("bindings").Parse(templateString)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err = parsedTemplate.Execute(&buf, r); err != nil {
		return "", err
	}

	return buf.String(), err
}

// vault expects bindings to be an hcl string
func (r gcpRoleSetEntry) MarshalJSON() ([]byte, error) {
	type Alias gcpRoleSetEntry
	bindingsAsHCL, err := r.BindingsAsHCL()
	if err != nil {
		return []byte{}, err
	}

	return json.Marshal(&struct {
		Bindings string `json:"bindings"`
		Alias
	}{
		Bindings: bindingsAsHCL,
		Alias:    (Alias)(r),
	})
}

func ConfigureGcpSecretsEngine(secretsEngine SecretsEngine) {

	var secretsEngineGCP SecretsEngineGCP

	// Read in GCP root configuration
	content, err := ioutil.ReadFile(Spec.ConfigurationPath + "/secrets-engines/" + secretsEngine.Path + "gcp.json")
	if err != nil {
		log.Fatal("GCP secrets engine config file for path ["+secretsEngine.Path+"] not found. Cannot configure engine.", err)
	}

	// Perform any substitutions
	contentstring := string(content)
	err = performSubstitutions(&contentstring, "secrets-engines/"+secretsEngine.Name)
	if err != nil {
		log.Warn(err)
		log.Warn("Secret substitution failed for [" + Spec.ConfigurationPath + "secrets-engines/" + secretsEngine.Path + "gcp.json" + "], skipping secret engine [" + secretsEngine.Path + "]")
		return
	}

	if !isJSON(contentstring) {
		log.Fatal("GCP secrets engine gcp.json for [" + secretsEngine.Path + "] is not a valid JSON file.")
	}

	err = json.Unmarshal([]byte(contentstring), &secretsEngineGCP)
	if err != nil {
		log.Fatal("Error parsing secret engine config for ["+secretsEngine.Path+"]", err)
	}

	// Get rolesets associated with this engine
	getGcpRoleSets(&secretsEngine, &secretsEngineGCP)

	// Write root config
	// Only write the root config if this is the first time setting up the engine
	// or if the overwrite_root_config flag is set
	if secretsEngine.JustEnabled || secretsEngineGCP.OverwriteRootCredentials {
		log.Debug("Writing root config for [" + secretsEngine.Path + "]. JustEnabled=" + strconv.FormatBool(secretsEngine.JustEnabled) + ", OverwriteRootCredentials=" + strconv.FormatBool(secretsEngineGCP.OverwriteRootCredentials))

		rootConfigPath := path.Join(secretsEngine.Path, "config")
		task := taskWrite{
			Path:        rootConfigPath,
			Description: fmt.Sprintf("GCP root config [%s]", rootConfigPath),
			Data:        structToMap(secretsEngineGCP.RootConfig),
		}
		wg.Add(1)
		taskChan <- task

	} else {
		log.Debug("Root config exists for [" + secretsEngine.Path + "], skipping...")
	}

	// Write config lease
	configLeasePath := path.Join(secretsEngine.Path, "config")
	task := taskWrite{
		Path:        configLeasePath,
		Description: fmt.Sprintf("GCP config lease [%s]", configLeasePath),
		Data:        structToMap(secretsEngineGCP.ConfigLease),
	}
	wg.Add(1)
	taskChan <- task

	// Create/Update RoleSets
	for roleset_name, roleset := range secretsEngineGCP.RoleSets {
		// log.Fatal(secretsEngineGCP.RoleSets["viewer"].BindingsAsHCL())
		rolesetPath := path.Join(secretsEngine.Path, "roleset", roleset_name)
		task := taskWrite{
			Path:        rolesetPath,
			Description: fmt.Sprintf("GCP roleset [%s]", rolesetPath),
			Data:        structToMap(roleset),
		}
		wg.Add(1)
		taskChan <- task
		if err != nil {
			log.Fatal("Error creating/updating roleset ["+roleset_name+"] at ["+secretsEngine.Path+"]", err)
		}
	}

	// Cleanup RoleSets
	cleanupGcpRoleSets(secretsEngine, secretsEngineGCP)
}

func getGcpRoleSets(secretsEngine *SecretsEngine, secretsEngineGCP *SecretsEngineGCP) {

	secretsEngineGCP.RoleSets = make(map[string]gcpRoleSetEntry)

	rolesetConfigDirPath := path.Join(Spec.ConfigurationPath, "secrets-engines", secretsEngine.Path, "rolesets")
	rawRoleSets := processDirectoryRaw(rolesetConfigDirPath)
	for rolesetName, rawRoleset := range rawRoleSets {
		var roleset gcpRoleSetEntry
		err := json.Unmarshal(rawRoleset, &roleset)
		if err != nil {
			log.Fatalf("Error parsing GCP roleset [%s]: %v", path.Join(rolesetConfigDirPath, rolesetName), err)
		}

		secretsEngineGCP.RoleSets[rolesetName] = roleset
	}
}

func cleanupGcpRoleSets(secretsEngine SecretsEngine, secretsEngineGCP SecretsEngineGCP) {

	existing_rolesets := getSecretList(secretsEngine.Path + "roleset")
	for _, roleset := range existing_rolesets {
		rolePath := secretsEngine.Path + "roleset/" + roleset
		if _, ok := secretsEngineGCP.RoleSets[roleset]; ok {
			log.Debug("[" + rolePath + "] exists in configuration, no cleanup necessary")
		} else {
			task := taskDelete{
				Description: fmt.Sprintf("GCP roleset [%s]", rolePath),
				Path:        rolePath,
			}
			taskPromptChan <- task
		}
	}
}
