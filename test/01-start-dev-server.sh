#!/bin/bash

. ../scripts/.env

# Stop existing stuff if it exists
docker stop vault-test > /dev/null 2>&1
docker rm vault-test > /dev/null 2>&1

# Create out docker network, if it doesn't exist
docker network create vault-admin-test > /dev/null 2>&1

# Run a local vault server
docker run \
  --name vault-test \
  -d \
  -p 8200:8200 \
  -e VAULT_ADDR=http://127.0.0.1:8200 \
  --network vault-admin-test \
  vault:1.10.4 server -dev-kv-v1

# Fix a recent issue relating to not being able to write to /tmp
docker container exec vault-test chmod    777    /tmp
docker container exec vault-test mkdir -m 777 -p /tmp/vault
