# Boundary Secrets Engine

## Usage

1. Enable secrets engine
```shell
vault secrets enable boundary
```

2. Configure secrets engine
```shell
vault write boundary/config \
  addr=http://localhost:9200 \
  login_name=admin \
  password=password \
  auth_method_id=ampw_1234567890
```

3. Create a role

```shell
vault write boundary/role/robert \
  ttl=180 \
  max_ttl=360 \
  auth_method_id=ampw_1234567890 \
  credential_type=userpass \
  boundary_roles=r_cbvEFZbN1S,r_r8mxdp7zOp \
  scope_id=global
```

4. Generate Boundary credentials
```shell
vault read boundary/creds/robert
```