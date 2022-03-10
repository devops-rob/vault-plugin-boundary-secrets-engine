package boundarysecrets

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configStoragePath = "config"
)

// boundaryConfig includes the minimum configuration
// required to instantiate a new boundary client.
type boundaryConfig struct {
	LoginName string `json:"login_name"`
	Password string `json:"password"`
	Addr      string `json:"addr"`
	AuthMethodId string `json:"auth_method_id"`
}

// pathConfig extends the Vault API with a `/config`
// endpoint for the backend. You can choose whether
// or not certain attributes should be displayed,
// required, and named. For example, password
// is marked as sensitive and will not be output
// when you read the configuration.
func pathConfig(b *boundaryBackend) *framework.Path {
	return &framework.Path{
		Pattern:         "config",
		Fields:          map[string]*framework.FieldSchema{
			"login_name": {
				Type: framework.TypeString,
				Description: "The Boundary Login Name that Vault will use to manage Boundary",
				Required: true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Login Name",
					Sensitive: false,
				},
			},
			"password": {
				Type: framework.TypeString,
				Description: "The password of the user that Vault will use to manage Boundary",
				Required: true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Password",
					Sensitive: true,
				},
			},
			"addr": {
				Type: framework.TypeString,
				Description: "The address of the Boundary controller",
				Required: true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Addr",
					Sensitive: false,
				},
			},
			"auth_method_id": {
				Type: framework.TypeString,
				Description: "The ID of the Boundary auth-method Vault will use to sign in",
				Required: true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Auth-method ID",
					Sensitive: false,
				},
			},
		},
		Operations:      map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigDelete,
			},
		},
		ExistenceCheck:  b.pathConfigExistenceCheck,
		HelpSynopsis:    pathConfigHelpSynopsis,
		HelpDescription: pathConfigHelpDescription,
	}
}

// pathConfigExistenceCheck verifies if the configuration exists.
func (b *boundaryBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}

	return out != nil, nil
}

func getConfig(ctx context.Context, s logical.Storage) (*boundaryConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	config := new(boundaryConfig)
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, fmt.Errorf("error reading root configuration: %w", err)
	}

	// return the config, we are done
	return config, nil
}

func (b *boundaryBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"login_name": config.LoginName,
			"addr": config.Addr,
			"auth_method_id": config.AuthMethodId,
		},
	}, nil
}

func (b *boundaryBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	createOperation := (req.Operation == logical.CreateOperation)

	if config == nil {
		if !createOperation {
			return nil, errors.New("config not found during update operation")
		}
		config = new(boundaryConfig)
	}

	if login_name, ok := data.GetOk("login_name"); ok {
		config.LoginName = login_name.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing login_name in configuration")
	}

	if addr, ok := data.GetOk("addr"); ok {
		config.Addr = addr.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing addr in configuration")
	}

	if password, ok := data.GetOk("password"); ok {
		config.Password = password.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing password in configuration")
	}

	if auth_method_id, ok := data.GetOk("auth_method_id"); ok {
		if strings.HasPrefix(auth_method_id.(string), "ampw_") {
			config.AuthMethodId = auth_method_id.(string)
		} else {
			return nil, fmt.Errorf("invalid auth_method_id type. Must be password auth method type")
		}
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing auth_method_id in configuration ")
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	b.reset()

	return nil, nil
}

func (b *boundaryBackend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, configStoragePath)

	if err == nil {
		b.reset()
	}

	return nil, err
}


// pathConfigHelpSynopsis summarizes the help text for the configuration
const pathConfigHelpSynopsis = `Configure the Boundary backend.`

// pathConfigHelpDescription describes the help text for the configuration
const pathConfigHelpDescription = `
The Boundary secret backend requires credentials for managing
Users, Groups, Grants and Roles.
You must sign up with a Login name and password and
specify the Boundary address and Auth-method ID
before using this secrets backend.
`
