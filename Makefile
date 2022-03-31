build:
	go build -o vault/plugins/boundary cmd/vault-plugin-secrets-boundary/main.go
test:
	go test -v