package boundarysecrets

import (
	"context"
	"strconv"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

const (
	roleName        = "testboundary"
	auth_method_id  = "ampw_1234567890"
	boundary_roles  = "r_cbvEFZbN1S,r_r8mxdp7zOp"
	scope_id        = "global"
	credential_type = "userpass"
	testTTL         = int64(120)
	testMaxTTL      = int64(3600)
	roleType        = "user"
	workerRoleName  = "testboundaryworker"
)

// TestUserRole uses a mock backend to check
// role create, read, update, and delete.
func TestUserRole(t *testing.T) {
	b, s := getTestBackend(t)

	t.Run("List All Roles", func(t *testing.T) {
		for i := 1; i <= 10; i++ {
			_, err := testTokenRoleCreate(t, b, s,
				roleName+strconv.Itoa(i),
				map[string]interface{}{
					"boundary_roles":       boundary_roles,
					"scope_id":             scope_id,
					"user_credential_type": credential_type,
					"auth_method_id":       auth_method_id,
					"ttl":                  testTTL,
					"max_ttl":              testMaxTTL,
					"role_type":            roleType,
				})
			require.NoError(t, err)
		}

		resp, err := testTokenRoleList(t, b, s)
		require.NoError(t, err)
		require.Len(t, resp.Data["keys"].([]string), 10)
	})

	t.Run("Create User Role - pass", func(t *testing.T) {
		resp, err := testTokenRoleCreate(t, b, s, roleName, map[string]interface{}{
			"boundary_roles":       boundary_roles,
			"scope_id":             scope_id,
			"user_credential_type": credential_type,
			"auth_method_id":       auth_method_id,
			"ttl":                  testTTL,
			"max_ttl":              testMaxTTL,
			//"login_name":           loginName,
			"role_type": roleType,
		})

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.Nil(t, resp)
	})

	t.Run("Read User Role", func(t *testing.T) {
		resp, err := testTokenRoleRead(t, b, s)

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.NotNil(t, resp)
		require.Equal(t, resp.Data["boundary_roles"], boundary_roles)
		require.Equal(t, resp.Data["auth_method_id"], auth_method_id)
		require.Equal(t, resp.Data["scope_id"], scope_id)
		//require.Equal(t, resp.Data["credential_type"], credential_type)
	})
	t.Run("Update User Role", func(t *testing.T) {
		resp, err := testTokenRoleUpdate(t, b, s, map[string]interface{}{
			"ttl":            "1m",
			"max_ttl":        "5h",
			"boundary_roles": "r_bauDEYaM2R",
			"scope_id":       "0_1234567890",
			"auth_method_id": "ampw_0987654321",
			"role_type":      roleType,
		})

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.Nil(t, resp)
	})

	t.Run("Re-read User Role", func(t *testing.T) {
		resp, err := testTokenRoleRead(t, b, s)

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.NotNil(t, resp)
		require.Equal(t, resp.Data["boundary_roles"], "r_bauDEYaM2R")
		require.Equal(t, resp.Data["scope_id"], "0_1234567890")
		require.Equal(t, resp.Data["auth_method_id"], "ampw_0987654321")
		require.Equal(t, resp.Data["ttl"], float64(60))
		require.Equal(t, resp.Data["max_ttl"], float64(18000))
	})

	t.Run("Delete User Role", func(t *testing.T) {
		_, err := testTokenRoleDelete(t, b, s)

		require.NoError(t, err)
	})
}

func TestWorkerRole(t *testing.T) {
	b, s := getTestBackend(t)

	t.Run("List All Roles", func(t *testing.T) {
		for i := 1; i <= 10; i++ {
			_, err := testTokenRoleCreate(t, b, s,
				workerRoleName+strconv.Itoa(i),
				map[string]interface{}{
					"scope_id":  scope_id,
					"ttl":       testTTL,
					"max_ttl":   testMaxTTL,
					"role_type": "worker",
				})
			require.NoError(t, err)
		}

		resp, err := testTokenRoleList(t, b, s)
		require.NoError(t, err)
		require.Len(t, resp.Data["keys"].([]string), 10)
	})

	t.Run("Create Worker Role - pass", func(t *testing.T) {
		resp, err := testTokenRoleCreate(t, b, s, roleName, map[string]interface{}{
			"scope_id":  scope_id,
			"ttl":       testTTL,
			"max_ttl":   testMaxTTL,
			"role_type": "worker",
		})

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.Nil(t, resp)
	})

	t.Run("Read Worker Role", func(t *testing.T) {
		resp, err := testTokenRoleRead(t, b, s)

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.NotNil(t, resp)
		require.Equal(t, resp.Data["scope_id"], scope_id)
		//require.Equal(t, resp.Data["credential_type"], credential_type)
	})
	t.Run("Update Worker Role", func(t *testing.T) {
		resp, err := testTokenRoleUpdate(t, b, s, map[string]interface{}{
			"ttl":       "1m",
			"max_ttl":   "5h",
			"scope_id":  "0_0987654321",
			"role_type": "worker",
		})

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.Nil(t, resp)
	})

	t.Run("Re-read Worker Role", func(t *testing.T) {
		resp, err := testTokenRoleRead(t, b, s)

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.NotNil(t, resp)
		require.Equal(t, resp.Data["scope_id"], "0_0987654321")
		require.Equal(t, resp.Data["ttl"], float64(60))
		require.Equal(t, resp.Data["max_ttl"], float64(18000))
	})

	t.Run("Delete Worker Role", func(t *testing.T) {
		_, err := testTokenRoleDelete(t, b, s)

		require.NoError(t, err)
	})
}

// Utility function to create a role while, returning any response (including errors)
func testTokenRoleCreate(t *testing.T, b *boundaryBackend, s logical.Storage, name string, d map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/" + name,
		Data:      d,
		Storage:   s,
	})

	if err != nil {
		return nil, err
	}

	return resp, nil
}

// Utility function to update a role while, returning any response (including errors)
func testTokenRoleUpdate(t *testing.T, b *boundaryBackend, s logical.Storage, d map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/" + roleName,
		Data:      d,
		Storage:   s,
	})

	if err != nil {
		return nil, err
	}

	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
	return resp, nil
}

// Utility function to read a role and return any errors
func testTokenRoleRead(t *testing.T, b *boundaryBackend, s logical.Storage) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/" + roleName,
		Storage:   s,
	})
}

// Utility function to list roles and return any errors
func testTokenRoleList(t *testing.T, b *boundaryBackend, s logical.Storage) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "role/",
		Storage:   s,
	})
}

// Utility function to delete a role and return any errors
func testTokenRoleDelete(t *testing.T, b *boundaryBackend, s logical.Storage) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "role/" + roleName,
		Storage:   s,
	})
}
