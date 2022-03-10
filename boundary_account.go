package boundarysecrets

import (
	"context"
	"errors"
	"fmt"
	"github.com/hashicorp/boundary/api/accounts"
	"github.com/hashicorp/boundary/api/roles"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/sethvargo/go-password/password"
	"log"
)

const (
	Account = "account"
)

type boundaryAccount struct {
	AccountId string `json:"account_id"`
	//Name string `json:"name"`
	AuthMethodId string `json:"auth_method_id"`
	LoginName  string `json:"login_name"`
	Password string `json:"password"`
	BoundaryRoles []string `json:"boundary_roles"`
}

func (b *boundaryBackend) boundaryAccount() *framework.Secret {
	return &framework.Secret{
		Type: Account,
		Revoke: b.accountRevoke,
		Renew: b.accountRenew,
		Fields: map[string]*framework.FieldSchema{
			"login_name": {
				Type: framework.TypeString,
				Description: "Login name for Boundary Account",
			},
			"password": {
				Type: framework.TypeString,
				Description: "Password for Boundary account associated with the Account",
			},
			"auth_method_id": {
				Type: framework.TypeString,
				Description: "Auth method ID associated with the Boundary Account",
			},
			"account_id": {
				Type: framework.TypeString,
				Description: "Boundary Account ID",
			},
			"boundary_roles": {
				Type: framework.TypeString,
				Description: "List of Boundary roles assigned to the Account",
			},
			//"name": {
			//	Type: framework.TypeLowerCaseString,
			//	Description: "Friendly name for Boundary Account",
			//},
		},
	}
}

// accountRevoke removes the token from the Vault storage API and calls the client to revoke the token
func (b *boundaryBackend) accountRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("error getting client: %w", err)
	}

	accountId := ""
	// We passed the token using InternalData from when we first created
	// the secret. This is because the HashiCups API uses the exact token
	// for revocation. From a security standpoint, your target API and client
	// should use a token ID instead!
	accountIdRaw, ok := req.Secret.InternalData["account_id"]
	if ok {
		accountId, ok = accountIdRaw.(string)
		if !ok {
			return nil, fmt.Errorf("invalid value for account_id in secret internal data")
		}
	}

	if err := deleteToken(ctx, client, accountId); err != nil {
		return nil, fmt.Errorf("error revoking account: %w", err)
	}
	return nil, nil
}

// tokenRenew calls the client to create a new token and stores it in the Vault storage API
func (b *boundaryBackend) accountRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleRaw, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, fmt.Errorf("secret is missing role internal data")
	}

	// get the role entry
	role := roleRaw.(string)
	roleEntry, err := b.getRole(ctx, req.Storage, role)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	resp := &logical.Response{Secret: req.Secret}

	if roleEntry.TTL > 0 {
		resp.Secret.TTL = roleEntry.TTL
	}
	if roleEntry.MaxTTL > 0 {
		resp.Secret.MaxTTL = roleEntry.MaxTTL
	}

	return resp, nil
}

// createToken calls the HashiCups client to sign in and returns a new token
func createAccount(ctx context.Context, c *boundaryClient, role string, authMethodID string, boundaryRoles []string) (*boundaryAccount, error) {


	// Accounts client
	aClient := accounts.NewClient(c.Client)

	// Setting up the loginName using role_id + randomly generated string
	loginNamePostfix, err := password.Generate(8, 0, 0, true, false)
	if err != nil {
		log.Fatal(err)
	}
	loginName := `vault-role-`+role+`-`+loginNamePostfix

	var accountOpts []accounts.Option
	accountOpts = append(accountOpts, accounts.WithPasswordAccountLoginName(loginName))
	accountOpts = append(accountOpts, accounts.WithName(loginName))

	// Generating a password
	accountPassword, err := password.Generate(16, 10, 0, false, false)
	if err != nil {
		log.Fatal(err)
	}

	accountOpts = append(accountOpts, accounts.WithPasswordAccountPassword(accountPassword))

	// Creating an account
	acr, err := aClient.Create(ctx, authMethodID, accountOpts...)
	if err != nil {

		return nil, err
	}

	var principalIds []string
	principalIds = append(principalIds, acr.Item.Id)

	rClient := roles.NewClient(c.Client)

	var boundaryRoleIds []string
	for s := range boundaryRoles {

		rcr, err := rClient.AddPrincipals(ctx, string(s), 1, principalIds)
		boundaryRoleIds = append(boundaryRoleIds, rcr.Item.Id)
		if err != nil {

			return nil, err
		}
	}

	return &boundaryAccount{
		AccountId:              acr.Item.Id,
		LoginName:       acr.Item.Name,
		Password: accountPassword,
		AuthMethodId: acr.Item.AuthMethodId,
		BoundaryRoles: boundaryRoleIds,
	}, nil

}

// deleteToken calls the HashiCups client to sign out and revoke the token
func deleteToken(ctx context.Context, c *boundaryClient, accountId string) error {
	// TODO - create the account using plugin and manually delete and test the vault revoke to see the error
	acr := accounts.NewClient(c.Client)

	var opts []accounts.Option
	_, err := acr.Delete(ctx, accountId, opts...)
	if err != nil {
		return err
	}

	return nil
}
