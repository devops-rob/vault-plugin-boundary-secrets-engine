package boundarysecrets

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathCredentials extends the Vault API with a `/creds`
// endpoint for a role. You can choose whether
// or not certain attributes should be displayed,
// required, and named.
func pathCredentials(b *boundaryBackend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role",
				Required:    true,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathCredentialsRead,
			logical.UpdateOperation: b.pathCredentialsRead,
		},
		HelpSynopsis:    pathCredentialsHelpSyn,
		HelpDescription: pathCredentialsHelpDesc,
	}
}

// pathCredentialsRead creates a new HashiCups token each time it is called if a
// role exists.
func (b *boundaryBackend) pathCredentialsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)

	roleEntry, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	return b.createUserCreds(ctx, req, roleEntry)
}

// createUserCreds creates a new HashiCups token to store into the Vault backend, generates
// a response with the secrets information, and checks the TTL and MaxTTL attributes.
func (b *boundaryBackend) createUserCreds(ctx context.Context, req *logical.Request, role *boundaryRoleEntry) (*logical.Response, error) {
	account, err := b.createAccount(ctx, req.Storage, role)
	if err != nil {
		return nil, err
	}

	// The response is divided into two objects (1) internal data and (2) data.
	// If you want to reference any information in your code, you need to
	// store it in internal data!
	resp := b.Secret(Account).Response(map[string]interface{}{
		"account_id":     account.AccountId,
		"boundary_roles": account.BoundaryRoles,
		"user_id": account.UserId,
		"auth_method_id": account.AuthMethodId,
		"password":       account.Password,
		"login_name":     account.LoginName,
	}, map[string]interface{}{
		"account_id": account.AccountId,
		"user_id": account.UserId,
	})

	if role.TTL > 0 {
		resp.Secret.TTL = role.TTL
	}

	if role.MaxTTL > 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}

	return resp, nil
}

// createAccount uses the Boundary client to create a new account
func (b *boundaryBackend) createAccount(ctx context.Context, s logical.Storage, roleEntry *boundaryRoleEntry) (*boundaryAccount, error) {
	client, err := b.getClient(ctx, s)
	if err != nil {
		return nil, err
	}

	var token *boundaryAccount

	token, err = createAccount(ctx, client, roleEntry.Name, roleEntry.AuthMethodID, roleEntry.BoundaryRoles, roleEntry.ScopeId)
	if err != nil {
		return nil, fmt.Errorf("error creating Boundary Account: %w", err)
	}

	if token == nil {
		return nil, errors.New("error creating Boundary Account")
	}

	return token, nil

}

const pathCredentialsHelpSyn = `
Generate a Boundary account from a specific Vault role.
`

const pathCredentialsHelpDesc = `
This path generates a Boundary account
based on a particular role.
`
