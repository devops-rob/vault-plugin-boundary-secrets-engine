package boundarysecrets

import (
	"context"
	"errors"
	"fmt"
	"github.com/hashicorp/boundary/api/accounts"
	"github.com/hashicorp/boundary/api/roles"
	"github.com/hashicorp/boundary/api/users"
	"github.com/hashicorp/boundary/api/workers"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/sethvargo/go-password/password"
	"log"
	"strings"
)

const (
	Account = "account"
	Worker  = "worker"
)

type boundaryAccount struct {
	AccountId     string `json:"account_id"`
	AuthMethodId  string `json:"auth_method_id"`
	LoginName     string `json:"login_name"`
	Password      string `json:"password"`
	BoundaryRoles string `json:"boundary_roles"`
	UserId        string `json:"user_id"`
}

type boundaryWorker struct {
	WorkerId        string `json:"worker_id"`
	ActivationToken string `json:"activation_token"`
	Description     string `json:"description"`
	WorkerName      string `json:"worker_name"`
}

func (b *boundaryBackend) boundaryAccount() *framework.Secret {
	return &framework.Secret{
		Type:   Account,
		Revoke: b.accountRevoke,
		Renew:  b.accountRenew,
		Fields: map[string]*framework.FieldSchema{
			"login_name": {
				Type:        framework.TypeString,
				Description: "Login name for Boundary Account",
			},
			"password": {
				Type:        framework.TypeString,
				Description: "Password for Boundary account associated with the Account",
			},
			"auth_method_id": {
				Type:        framework.TypeString,
				Description: "Auth method ID associated with the Boundary Account",
			},
			"account_id": {
				Type:        framework.TypeString,
				Description: "Boundary Account ID",
			},
			"user_id": {
				Type:        framework.TypeString,
				Description: "Boundary User ID",
			},
			"boundary_roles": {
				Type:        framework.TypeString,
				Description: "List of Boundary roles assigned to the Account",
			},
		},
	}
}

func (b *boundaryBackend) boundaryWorker() *framework.Secret {
	return &framework.Secret{
		Type:   Worker,
		Revoke: b.workerRevoke,
		Renew:  b.workerRenew,
		Fields: map[string]*framework.FieldSchema{
			"worker_name": {
				Type:        framework.TypeString,
				Description: "Name for Boundary worker",
			},
			"worker_id": {
				Type:        framework.TypeString,
				Description: "ID for Boundary worker",
			},
			"activation_token": {
				Type:        framework.TypeString,
				Description: "Activation token for Boundary worker",
			},
			"description": {
				Type:        framework.TypeString,
				Description: "Description of Boundary worker",
			},
		},
	}
}

// accountRevoke removes the token from the Vault storage API and calls the client to revoke the token
func (b *boundaryBackend) accountRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("error getting client: %w", err)
	}

	userId := ""
	userIdRaw, ok := req.Secret.InternalData["user_id"]
	if ok {
		userId, ok = userIdRaw.(string)
		if !ok {
			return nil, fmt.Errorf("invalid value for user_id in secret internal data")
		}
	}

	accountId := ""
	accountIdRaw, ok := req.Secret.InternalData["account_id"]
	if ok {
		accountId, ok = accountIdRaw.(string)
		if !ok {
			return nil, fmt.Errorf("invalid value for account_id in secret internal data")
		}
	}

	if err := deleteToken(ctx, client, accountId, userId); err != nil {
		return nil, fmt.Errorf("error revoking account: %w", err)
	}
	return nil, nil
}

func (b *boundaryBackend) workerRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("error getting client: %w", err)
	}

	workerId := ""
	workerIdRaw, ok := req.Secret.InternalData["worker_id"]
	if ok {
		workerId, ok = workerIdRaw.(string)
		if !ok {
			return nil, fmt.Errorf("invalid value for worker_id in secret internal data")
		}
	}

	if err := deleteWorker(ctx, client, workerId); err != nil {
		return nil, fmt.Errorf("error revoking worker")
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

func (b *boundaryBackend) workerRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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

// createToken calls the Boundary client and creates a new Boundary account
func createAccount(ctx context.Context, c *boundaryClient, role string, authMethodID string, boundaryRoles string, scopeId string) (*boundaryAccount, error) {

	// Accounts client
	aClient := accounts.NewClient(c.Client)

	// Setting up the loginName using role_id + randomly generated string
	loginNamePostfix, err := password.Generate(8, 0, 0, true, false)
	if err != nil {
		log.Fatal(err)
	}
	loginName := `vault-role-` + role + `-` + loginNamePostfix

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

	uclient := users.NewClient(c.Client)

	var userOpts []users.Option

	userOpts = append(userOpts, users.WithName(loginName))

	ucr, err := uclient.Create(ctx, scopeId, userOpts...)
	if err != nil {

		return nil, err
	}
	var accountList []string
	accountList = append(accountList, acr.Item.Id)
	_, err = uclient.AddAccounts(ctx, ucr.Item.Id, ucr.Item.Version, accountList)
	if err != nil {

		return nil, err
	}

	var principalIds []string
	principalIds = append(principalIds, ucr.Item.Id)

	rClient := roles.NewClient(c.Client)

	var boundaryRoleIds []string
	var rolesList []string

	rolesList = strings.Split(boundaryRoles, ",")

	var boundaryRoleIdsString string

	for _, s := range rolesList {

		var opts []roles.Option
		version, err := rClient.Read(ctx, s, opts...)
		if err != nil {
			return nil, err
		}

		rcr, err := rClient.AddPrincipals(ctx, s, version.Item.Version, principalIds, opts...)
		if err != nil {
			return nil, err
		}

		boundaryRoleIds = append(boundaryRoleIds, rcr.Item.Id)
	}
	boundaryRoleIdsString = strings.Join(boundaryRoleIds, ",")

	return &boundaryAccount{
		AccountId:     acr.Item.Id,
		LoginName:     acr.Item.Name,
		Password:      accountPassword,
		AuthMethodId:  acr.Item.AuthMethodId,
		BoundaryRoles: boundaryRoleIdsString,
		UserId:        ucr.Item.Id,
	}, nil
}

// deleteToken calls the boundary client to remove account
func deleteToken(ctx context.Context, c *boundaryClient, accountId string, userId string) error {
	ucr := users.NewClient(c.Client)
	var userOpts []users.Option
	_, err := ucr.Delete(ctx, userId, userOpts...)
	if err != nil {
		return err
	}

	acr := accounts.NewClient(c.Client)

	var opts []accounts.Option
	_, err = acr.Delete(ctx, accountId, opts...)
	if err != nil {
		return err
	}

	return nil
}

func createWorker(ctx context.Context, c *boundaryClient, scopeId string, workerName string, description string) (*boundaryWorker, error) {
	wcl := workers.NewClient(c.Client)
	var workerOpts []workers.Option
	workerOpts = append(workerOpts, workers.WithAutomaticVersioning(true))
	workerOpts = append(workerOpts, workers.WithDescription(description))
	workerOpts = append(workerOpts, workers.WithName(workerName))
	wcr, err := wcl.CreateControllerLed(ctx, scopeId, workerOpts...)
	if err != nil {
		return nil, err
	}

	return &boundaryWorker{
		WorkerId:        wcr.Item.Id,
		ActivationToken: wcr.Item.ControllerGeneratedActivationToken,
		WorkerName:      wcr.Item.Name,
		Description:     wcr.Item.Description,
	}, nil
}

func deleteWorker(ctx context.Context, c *boundaryClient, workerId string) error {
	wcl := workers.NewClient(c.Client)
	var workerOpts []workers.Option

	_, err := wcl.Delete(ctx, workerId, workerOpts...)
	if err != nil {
		return err
	}

	return nil
}
