package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path"
	"path/filepath"

	VaultApi "github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
)

type authMethod struct {
	Name             string
	Path             string                     `json:"path"`
	AuthOptions      VaultApi.EnableAuthOptions `json:"auth_options"`
	Config           map[string]interface{}     `json:"config"`
	AdditionalConfig interface{}                `json:"additional_config"`
}

type authMethodList map[string]authMethod

func SyncAuthMethods() {

	authMethodList := authMethodList{}

	log.Info("Syncing Auth Methods")
	getAuthMethods(authMethodList)
	configureAuthMethods(authMethodList)
	cleanupAuthMethods(authMethodList)
}

func getAuthMethods(authMethodList authMethodList) {
	files, err := ioutil.ReadDir(Spec.ConfigurationPath + "/auth_methods/")
	if err != nil {
		log.Debug("No auth methods found: ", err)
	}

	for _, file := range files {

		// Use the filename as the mount path
		var m authMethod
		filename := file.Name()
		m.Name = filename[0 : len(filename)-len(filepath.Ext(filename))]
		m.Path = m.Name + "/"

		if checkExt(filename, ".json") {
			content, err := ioutil.ReadFile(Spec.ConfigurationPath + "/auth_methods/" + file.Name())
			if err != nil {
				log.Fatal(err)
			}

			contentstring := string(content)

			if !isJSON(string(content)) {
				log.Fatal("Auth method configuration not valid JSON: ", file.Name())
			}

			err = performSubstitutions(&contentstring, "auth_methods/"+m.Path)
			if err != nil {
				log.Warn(err)
				log.Fatalf("Secret substitution failed for: %s", m.Path)
			}

			if !isJSON(contentstring) {
				log.Fatalf("Auth method [%s] is not a valid JSON after secret substitution", m.Path)
			}

			err = json.Unmarshal([]byte(contentstring), &m)
			if err != nil {
				log.Fatal("Error parsing auth method configuration: ", file.Name(), " ", err)
			}

			authMethodList[m.Path] = m
		} else {
			log.Warn("Auth file has wrong extension.  Will not be processed: ", Spec.ConfigurationPath+"auth_methods/"+file.Name())
		}
	}
}

func configureAuthMethods(authMethodList authMethodList) {
	for _, mount := range authMethodList {

		// Check if mount is enabled
		existing_mounts, _ := VaultSys.ListAuth()
		if _, ok := existing_mounts[mount.Path]; ok {
			if existing_mounts[mount.Path].Type != mount.AuthOptions.Type {
				log.Fatal("Auth mount path  "+mount.Path+" exists but doesn't match type: ", existing_mounts[mount.Path].Type, "!=", mount.AuthOptions.Type)
			}
			var mc VaultApi.MountConfigInput
			mc.DefaultLeaseTTL = mount.AuthOptions.Config.DefaultLeaseTTL
			mc.MaxLeaseTTL = mount.AuthOptions.Config.MaxLeaseTTL
			mc.ListingVisibility = mount.AuthOptions.Config.ListingVisibility
			mc.Description = &mount.AuthOptions.Description

			tunePath := path.Join("sys/auth", mount.Path, "tune")
			task := taskWrite{
				Path:        tunePath,
				Description: fmt.Sprintf("Auth mount tune for [%s]", tunePath),
				Data:        structToMap(mc),
			}
			wg.Add(1)
			taskChan <- task

		} else {
			log.Debug("Auth mount path " + mount.Path + " is not enabled, enabling")
			err := VaultSys.EnableAuthWithOptions(mount.Path, &mount.AuthOptions)
			if err != nil {
				log.Fatal("Error enabling mount: ", mount.Path, " ", mount.AuthOptions.Type, " ", err)
			}
			log.Info("Auth enabled: ", mount.Path, " ", mount.AuthOptions.Type)
		}

		// Write the auth configuration (if set)
		if mount.Config != nil {

			// Here we transform to json in order to do string substitution
			// jsondata, err := json.Marshal(mount.Config)
			// if err != nil {
			// 	log.Fatal(err)
			// }
			// contentstring := string(jsondata)
			// err = performSubstitutions(&contentstring, "auth_methods/"+mount.Name)
			// if err != nil {
			// 	log.Warn(err)
			// 	log.Warnf("Secret substitution failed for [%s], skipping auth method configuration", mount.Path)
			// 	return
			// } else {
			// 	if !isJSON(contentstring) {
			// 		log.Fatalf("Auth engine [%s] is not a valid JSON after secret substitution", mount.Path)
			// 	}

			// 	var configMap map[string]interface{}
			// 	if err := json.Unmarshal([]byte(contentstring), &configMap); err != nil {
			// 		log.Fatalf("Auth engine [%s] failed to unmarshall after secret substitution", mount.Path)
			// 	}

			configPath := path.Join("auth", mount.Path, "config")
			task := taskWrite{
				Path:        configPath,
				Description: fmt.Sprintf("Auth mount config for [%s]", configPath),
				Data:        mount.Config,
			}
			wg.Add(1)
			taskChan <- task
			// }
		}

		if mount.AuthOptions.Type == "userpass" {
			log.Info("Running additional configuration for ", mount.Path)
			configureUserpassAuth(mount)
		} else if mount.AuthOptions.Type == "ldap" {
			log.Info("Running additional configuration for ", mount.Path)
			configureLDAPAuth(mount)
		} else if mount.AuthOptions.Type == "jwt" || mount.AuthOptions.Type == "oidc" {
			authMethodJWT := AuthMethodJWT{
				Path:             path.Join("auth", mount.Path),
				AdditionalConfig: mount.AdditionalConfig,
			}
			log.Infof("Running additional configuration for [%s]", authMethodJWT.Path)
			authMethodJWT.Configure()
		} else if mount.AuthOptions.Type == "kubernetes" {
			authMethodKubernetes := AuthMethodKubernetes{
				Path:             path.Join("auth", mount.Path),
				AdditionalConfig: mount.AdditionalConfig,
			}
			log.Infof("Running additional configuration for [%s]", authMethodKubernetes.Path)
			authMethodKubernetes.Configure()
		} else {
			log.Warnf(`Auth type "%s" not currently supported, please open PR!`, mount.AuthOptions.Type)
		}

	}
}

func cleanupAuthMethods(authMethodList authMethodList) {
	existing_mounts, _ := VaultSys.ListAuth()

	for mountPath, mount := range existing_mounts {

		// Ignore default token auth mount
		if !(mountPath == "token/" && mount.Type == "token") {
			if _, ok := authMethodList[mountPath]; ok {
				log.Debug(mountPath + " exists in configuration, no cleanup necessary")
			} else {
				authPath := path.Join("sys/auth", mountPath)
				task := taskDelete{
					Description: fmt.Sprintf("Auth method [%s]", authPath),
					Path:        authPath,
				}
				taskPromptChan <- task
			}
		}
	}
}
