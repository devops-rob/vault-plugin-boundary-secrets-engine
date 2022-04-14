# Boundary Secrets Engine for HashiCorp Vault

The Boundary secrets engine generates user and account credentials dynamically based on configured permissions and scopes. This means that services that need to access a Boundary scope no longer need to hardcode credentials.

With every service accessing Boundary with unique credentials, auditing is much easier in threat modelled scenarios.

Vault makes use both of its own internal revocation system to delete Boundary users and accounts when generating Boundary credentials to ensure that users and accounts become invalid within a reasonable time of the lease expiring.

## Setup

Most secrets engines must be configured in advance before they can perform their functions. These steps are usually completed by an operator or configuration management tool.


1. Enable secrets engine:


```shell
vault secrets enable boundary
```

By default, the secrets engine will mount at the name of the engine. To enable the secrets engine at a different path, use the -path argument.


2. Configure the credentials that Vault uses to communicate with Boundary to generate credentials:
```shell
vault write boundary/config \
  addr=http://localhost:9200 \
  login_name=admin \
  password=password \
  auth_method_id=ampw_1234567890
```
It is important that the Vault user have the permissions to manage users and accounts at all scope levels.

3. Configure a role that maps a name in Vault to a Boundary scope and roles:

```shell
vault write boundary/role/my-role \
  ttl=180 \
  max_ttl=360 \
  auth_method_id=ampw_1234567890 \
  credential_type=userpass \
  boundary_roles=r_cbvEFZbN1S,r_r8mxdp7zOp \
  scope_id=global
```

By writing to the roles/my-role path we are defining the my-role role. This role will be created by evaluating the given `auth_method_id`, `boundary_roles`, `scope_id`, `ttl` and `max_ttl` statements. Credentials generated against this role will be created at the specified scope, using the specified auth method, and will have the specified boundary roles assigned for the duration of the ttl specified. You can read more about [Boundary's Identity and Access Management domain.](https://www.hashicorp.com/blog/understanding-the-boundary-identity-and-access-management-model)

## Usage

After the secrets engine is configured and a user/machine has a Vault token with the proper permission, it can generate credentials.

1. Generate a new credential by reading from the /creds endpoint with the name of the role:
```shell
vault read boundary/creds/my-role
```

## API

### Setup

1. Enable secrets engine

Sample request

```shell
curl \
    -X POST \
    --header "X-Vault-Token: ..." \
    http://127.0.0.1:8200/v1/sys/mounts
```

Sample payload

```json
{
    "type": "boundary"
}
```

2. Configure the credentials that Vault uses to communicate with Boundary to generate credentials:

Sample request
```shell
curl \
    -X POST \
    --header "X-Vault-Token: ..." \
    http://127.0.0.1:8200/v1/boundary/config
```

Sample payload
```json
{
  "addr": "http://localhost:9200",
  "login_name": "vault-admin",
  "password": "...",
  "auth_method_id": "ampw_1234567890"
}
```

3. Configure a role that maps a name in Vault to a Boundary scope and roles:

Sample request
```shell
curl \
    -X POST \
    --header "X-Vault-Token: ..." \
    http://127.0.0.1:8200/v1/boundary/role/my-role
```

Sample payload
```json
{
    "ttl": 180,
    "max_ttl": 360,
    "auth_method_id": "ampw_1234567890",
    "credential_type": "userpass",
    "boundary_roles": "r_cbvEFZbN1S,r_r8mxdp7zOp",
    "scope_id": "global"
}
```

### Usage

1. Generate a new credential by reading from the /creds endpoint with the name of the role:

Sample request
```shell
curl \
    -X GET \
    --header "X-Vault-Token: ..." \
    http://127.0.0.1:8200/v1/boundary/creds/my-role
```

Sample response
```json
{
    "request_id": "ed281bc6-182d-a15e-d700-8c2e64897010",
    "lease_id": "boundary/creds/my-role/pH9CfQcAmE9va6CwQKOEPBsx",
    "renewable": true,
    "lease_duration": 180,
    "data": {
        "account_id": "acctpw_Haufl3nWxH",
        "auth_method_id": "ampw_1234567890",
        "boundary_roles": "r_CSuslu0w1X,r_S0OqRsecY6",
        "login_name": "vault-role-my-role-fudjntgy",
        "password": "2QW7U03mXr614895",
        "user_id": "u_sKom7Pxa1v"
    },
    "wrap_info": null,
    "warnings": null,
    "auth": null
}
```

## Terraform

### Setup

1. Enable secrets engine:

```hcl
resource "vault_mount" "boundary" {
  path        = "boundary"
  type        = "boundary"
  description = "This is the boundary secrets engine"
}
```

2. Configure the credentials that Vault uses to communicate with Boundary to generate credentials:

```hcl
resource "vault_generic_endpoint" "boundary_config" {
  depends_on           = [
    vault_mount.boundary
  ]
  
  path                 = "boundary/config"
  ignore_absent_fields = true

  data_json = <<EOT
{
  "addr": "http://localhost:9200",
  "login_name": "vault-admin",
  "password": "...",
  "auth_method_id": "ampw_1234567890"
}
EOT
}

```

3. Configure a role that maps a name in Vault to a Boundary scope and roles:

```hcl
resource "vault_generic_endpoint" "boundary_role" {
  depends_on           = [
    vault_mount.boundary
  ]
  
  path                 = "boundary/role/my-role"
  ignore_absent_fields = true

  data_json = <<EOT
{
    "ttl": 180,
    "max_ttl": 360,
    "auth_method_id": "ampw_1234567890",
    "credential_type": "userpass",
    "boundary_roles": "r_cbvEFZbN1S,r_r8mxdp7zOp",
    "scope_id": "global"
}
EOT
}
```

## Usage

1. Generate a new credential by reading from the /creds endpoint with the name of the role:

```hcl
data "vault_generic_secret" "boundary_creds" {
  path = "boundary/creds/my-role"
}

output "creds" {
  value     = data.vault_generic_secret.boundary_creds.data
  sensitive = true
}
```

2. Read the output from Terraform's state file:

```shell
terraform output creds
```

Example response:

```
tomap({
  "account_id" = "acctpw_nNaPX7PYzl"
  "auth_method_id" = "ampw_1234567890"
  "boundary_roles" = "r_U2t8YBalKE,r_5hKAwk9Rs9"
  "login_name" = "vault-role-my-role-tewohlyv"
  "password" = "4Le8z639725g0f1G"
  "user_id" = "u_TxJs1IabfY"
})
```