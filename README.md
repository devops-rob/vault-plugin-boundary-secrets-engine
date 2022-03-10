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
vault write boundary/role/rob \
  ttl=90 \
  max_ttl=360 \
  scope_id=o_1234567890 \
  auth_method_id=ampw_joMCbyL7qW \
  role_type=userpass
```

4. Generate Boundary credentials
```shell
vault read boundary/creds/rob
```