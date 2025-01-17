# Example Configuration Directory
This directory contains an examples of how to use the Vault Admin tool to configure Vault.  The top level subdirectories indicate the type of configuration.  The specific folder and file names below that are used as the name of the Vault mounts, policies, etc..  For the most part, the configurations are very closely tied to the Vault API spec

### Audit Devices
Set up audit devices. See [Audit Devices](https://www.vaultproject.io/docs/audit/index.html).

### Auth Methods
Currently the only supported methods are `userpass` and `ldap`.

#### LDAP
See [Audit Devices (LDAP)](https://www.vaultproject.io/docs/auth/ldap.html). The configuration for an LDAP auth method includes the LDAP server config as well as the LDAP group->Vault policy mapping (`policy_map`).  This tells Vault which LDAP groups map to which Vault policies.

#### Userpass
This method uses Vault's internal storage for users. Users are configured here.

### Policies
This is pretty straight-forward.  Each file in the `policies` directory represents one Vault policy.  The name of the file is used as the name of the policy. See [Vault Policies](https://www.vaultproject.io/docs/concepts/policies.html).

### Secrets Engines
Currently the only supported secrets engines are `aws`, `database` and Vault's built-in `identity` backend. See [Secrets Engines](https://www.vaultproject.io/docs/secrets/index.html).

Each directory under the `secrets-engines` directory contains the configuration for one engine. See the example folders for the exact syntax.  The directory structure is laid out like so:

```
├── secrets-engines/
│   ├── aws-main/ # Directory name will be the name of the secrets engine mount
│   │   ├── aws.json # Configuration for the AWS secrets engine
│   │   ├── config.json # Configuration for the secrets engine mount
│   │   ├── roles/ # Defines the AWS IAM Policies for each role (filename=role name)
│   │   │   ├── admin.json
│   │   │   ├── s3-read-only.json
│   │   │   ├── s3-read-write.json
│   │   │   └── sqs.json
│   ├── db-dev/ # Directory name will be the name of the secrets engine mount
│   │   ├── db.json # Configuration for the DB secrets engine
│   │   ├── config.json # Configuration for the secrets engine mount
│   │   ├── roles/ # Defines the DB grants for each role (filename=role name)
│   │   │   ├── admin.json
│   │   │   ├── read-only.json
│   │   │   └── read-write.json
│   ├── identity/ # Configures Vault's built-in identity engine
│   │   ├── entities/ # Defines identity entities (filename=entity name)
│   │   │   ├── usera.json
│   │   │   └── userb.json
│   │   ├── groups/ # Defines identity groups (filename=group name)
│   │   │   ├── groupa.json
│   │   │   └── groupb.json
```

Because secrets engines' configuration rely on having root credentials to the underlying system, we've built in a way to pull those credentials straight out of Vault's key/value store. For example, in the [secrets-engines/aws-main/aws.json](secrets-engines/aws-main/aws.json) configuration, in place of the actual `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` values, we put substitution values to be pulled out of Vault (`%{AWS_ACCESS_KEY_ID}%` and `%{AWS_SECRET_ACCESS_KEY}%`). These represent secret keys located within the default path `secret/vault-admin/`.  This path can be configured with the `VAULT_SECRET_BASE_PATH` configuration option (see main [README.md](../README.md)).

For example, with the `aws-main` secrets engine, we would need a secret with the path `secret/vault-admin/secrets-engines/aws-main` that contained two keys: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` with the appropriate values.
