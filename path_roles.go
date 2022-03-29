package boundarysecrets

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"time"
)

type boundaryRoleEntry struct {
	AuthMethodID  string        `json:"auth_method_id"`
	Name          string        `json:"name"`
	ScopeId       string        `json:"scope_id"`
	LoginName     string        `json:"login_name"`
	Password      string        `json:"password"`
	BoundaryRoles string      `json:"boundary_roles"`
	TTL           time.Duration `json:"ttl"`
	MaxTTL        time.Duration `json:"max_ttl"`
}

func (r *boundaryRoleEntry) toResponseData() map[string]interface{} {
	respData := map[string]interface{}{
		"ttl":            r.TTL.Seconds(),
		"max_ttl":        r.MaxTTL.Seconds(),
		"login_name":     r.LoginName,
		"boundary_roles": r.BoundaryRoles,
		"name":           r.Name,
		"auth_method_id": r.AuthMethodID,
		"scope_id":       r.ScopeId,
	}
	return respData
}

// TODO - add schema below from struct above
func pathRole(b *boundaryBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "role/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of Role",
					Required:    true,
				},
				"boundary_roles": {
					Type:        framework.TypeString, // This should be a list of Boundary roles
					Description: "List of Boundary roles to be assigned to generated users.",
					Required:    false,
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Default lease for generated credentials. If not set or set to 0, will use system default.",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum time for role. If not set or set to 0, will use system default.",
				},
				"scope_id": {
					Type:        framework.TypeLowerCaseString, // Boundary scope ID under which Users will be created
					Description: "Boundary scope ID of the Vault generated user",
				},
				"auth_method_id": {
					Type:        framework.TypeLowerCaseString, // Boundary auth method ID that the account is created under
					Description: "Boundary auth method ID that the account is created under",
				},
				"credential_type": {
					Type:        framework.TypeLowerCaseString,
					Description: "Vault role type. Currently only supports `userpass` type.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRolesRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRolesDelete,
				},
			},
			HelpSynopsis:    pathRoleHelpSynopsis,
			HelpDescription: pathRoleHelpDescription,
		},
		{
			Pattern: "role/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRolesList,
				},
			},
			HelpSynopsis:    pathRoleListHelpSynopsis,
			HelpDescription: pathRoleListHelpDescription,
		},
	}
}

const (
	pathRoleHelpSynopsis    = `Manages the Vault role for generating Boundary users.`
	pathRoleHelpDescription = `
This path allows you to read and write roles used to generate Boundary users.
`
	pathRoleListHelpSynopsis    = `List the existing roles in Boundary backend`
	pathRoleListHelpDescription = `Roles will be listed by the role name.`
)

func (b *boundaryBackend) getRole(ctx context.Context, s logical.Storage, name string) (*boundaryRoleEntry, error) {
	if name == "" {
		return nil, fmt.Errorf("missing role name")
	}

	entry, err := s.Get(ctx, "role/"+name)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var role boundaryRoleEntry

	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}
	return &role, nil
}

func (b *boundaryBackend) pathRolesRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entry, err := b.getRole(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: entry.toResponseData(),
	}, nil
}

func setRole(ctx context.Context, s logical.Storage, name string, roleEntry *boundaryRoleEntry) error {
	entry, err := logical.StorageEntryJSON("role/"+name, roleEntry)
	if err != nil {
		return err
	}

	if entry == nil {
		return fmt.Errorf("failed to create storage entry for role")
	}

	if err := s.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}

func (b *boundaryBackend) pathRolesWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("missing role name"), nil
	}

	roleEntry, err := b.getRole(ctx, req.Storage, name.(string))
	if err != nil {
		return nil, err
	}

	if roleEntry == nil {
		roleEntry = &boundaryRoleEntry{}
	}

	createOperation := (req.Operation == logical.CreateOperation)

	//if login_name, ok := d.GetOk("login_name"); ok {
	//	roleEntry.LoginName = login_name.(string)
	//} else if !ok && createOperation {
	//	return nil, fmt.Errorf("missing username in role")
	//}

	if name, ok := d.GetOk("name"); ok {
		roleEntry.Name = name.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing name of role")
	}

	// Check there is a list of boundary roles
	if boundaryRoles, ok := d.GetOk("boundary_roles"); ok {
		roleEntry.BoundaryRoles = boundaryRoles.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing boundary_roles in role")
	}

	// Check there is an auth method id
	if authMethodID, ok := d.GetOk("auth_method_id"); ok {
		roleEntry.AuthMethodID = authMethodID.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing auth_method_id in role")
	}

	// Check there is a scope id
	if scopeId, ok := d.GetOk("scope_id"); ok {
		roleEntry.ScopeId = scopeId.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing scope_id in role")
	}

	if ttlRaw, ok := d.GetOk("ttl"); ok {
		roleEntry.TTL = time.Duration(ttlRaw.(int)) * time.Second
	} else if createOperation {
		roleEntry.TTL = time.Duration(d.Get("ttl").(int)) * time.Second
	}

	if maxTTLRaw, ok := d.GetOk("max_ttl"); ok {
		roleEntry.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	} else if createOperation {
		roleEntry.MaxTTL = time.Duration(d.Get("max_ttl").(int)) * time.Second
	}

	if roleEntry.MaxTTL != 0 && roleEntry.TTL > roleEntry.MaxTTL {
		return logical.ErrorResponse("ttl cannot be greater than max_ttl"), nil
	}

	if err := setRole(ctx, req.Storage, name.(string), roleEntry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *boundaryBackend) pathRolesDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "role/"+d.Get("name").(string))
	if err != nil {
		return nil, fmt.Errorf("error deleting boundary role: %w", err)
	}

	return nil, nil
}

func (b *boundaryBackend) pathRolesList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}
