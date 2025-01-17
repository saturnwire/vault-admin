package main

import (
	log "github.com/sirupsen/logrus"
)

// Rotate backend credentials - currently just AWS
func RotateCreds() {
	existing_mounts, _ := VaultSys.ListMounts()
	for path, mount := range existing_mounts {
		if mount.Type == "aws" {
			secret, err := Vault.Write(path+"config/rotate-root", nil)
			if err != nil {
				log.Warn("Cannot rotate ["+path+"] ", err)
			} else {
				log.Info("Rotated key for ["+path+"].  New access key: ", secret.Data["access_key"].(string))
			}
		}
		if mount.Type == "gcp" {
			secret, err := Vault.Write(path+"config/rotate-root", nil)
			if err != nil {
				log.Warn("Cannot rotate ["+path+"] ", err)
			} else {
				log.Info("Rotated key for ["+path+"].  New private key id: ", secret.Data["private_key_id"].(string))
			}
		}
	}
}
