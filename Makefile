name = boundary
plugin_type = secrets-engine
version = 1.0.0

build:
	go build -o vault/plugins/boundary cmd/vault-plugin-secrets-boundary/main.go
test:
	go test -v
multi_build:
	@echo ""
	@echo "Compile Provider"

	# Clear the output
	rm -rf ./bin

	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o ./bin/linux_arm64/vault-plugin-$(name)-$(plugin_type)_v$(version) cmd/vault-plugin-secrets-$(name)/main.go
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o ./bin/linux_amd64/vault-plugin-$(name)-$(plugin_type)_v$(version) cmd/vault-plugin-secrets-$(name)/main.go
	GOOS=darwin GOARCH=arm64 go build -o ./bin/darwin_arm64/vault-plugin-$(name)-$(plugin_type)_v$(version) cmd/vault-plugin-secrets-$(name)/main.go
	GOOS=darwin GOARCH=amd64 go build -o ./bin/darwin_amd64/vault-plugin-$(name)-$(plugin_type)_v$(version) cmd/vault-plugin-secrets-$(name)/main.go
	GOOS=windows GOARCH=amd64 go build -o ./bin/windows_amd64/vault-plugin-$(name)-$(plugin_type)_v$(version).exe cmd/vault-plugin-secrets-$(name)/main.go
	GOOS=windows GOARCH=386 go build -o ./bin/windows_386/vault-plugin-$(name)-$(plugin_type)_v$(version).exe cmd/vault-plugin-secrets-$(name)/main.go
zip:
	pwd
	zip -j ./bin/vault-plugin-$(name)-$(plugin_type)_v$(version)_linux_arm64.zip ./bin/linux_arm64/vault-plugin-$(name)-$(plugin_type)_v$(version)
	zip -j ./bin/vault-plugin-$(name)-$(plugin_type)_v$(version)_linux_amd64.zip ./bin/linux_arm64/vault-plugin-$(name)-$(plugin_type)_v$(version)
	zip -j ./bin/vault-plugin-$(name)-$(plugin_type)_v$(version)_darwin_arm64.zip ./bin/linux_arm64/vault-plugin-$(name)-$(plugin_type)_v$(version)
	zip -j ./bin/vault-plugin-$(name)-$(plugin_type)_v$(version)_darwin_amd64.zip ./bin/linux_arm64/vault-plugin-$(name)-$(plugin_type)_v$(version)
	zip -j ./bin/vault-plugin-$(name)-$(plugin_type)_v$(version)_windows_amd64.zip ./bin/windows_amd64/vault-plugin-$(name)-$(plugin_type)_v$(version).exe
	zip -j ./bin/vault-plugin-$(name)-$(plugin_type)_v$(version)_windows_386.zip ./bin/windows_386/vault-plugin-$(name)-$(plugin_type)_v$(version).exe
	ls -lha ./bin

