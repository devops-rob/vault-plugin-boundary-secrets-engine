package boundarysecrets

import (
	"context"
	"errors"
	"fmt"
	"time"

	boundary "github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
)

const (
	tokenExpirationTimeAttribName = "expiration_time"
	loginNameAttribName           = "login_name"
	passwordAttribName            = "password"
	tokenAttribName               = "token"
)

type boundaryClient struct {
	*boundary.Client
	tokenExp time.Time
	config   *boundaryConfig
}

// newClient creates a new boundary client and authenticates it with the
// provided configuration
func newClient(config *boundaryConfig) (*boundaryClient, error) {

	if config == nil {
		return nil, errors.New("client configuration was nil")
	}

	if config.LoginName == "" {
		return nil, errors.New("login name was not defined")
	}

	if config.Password == "" {
		return nil, errors.New("password was not defined")
	}

	if config.Addr == "" {
		return nil, errors.New("boundary address was not defined")
	}

	if config.AuthMethodId == "" {
		return nil, errors.New("auth-method ID was not defined")
	}

	cfg := boundary.Config{
		Addr: config.Addr,
	}

	client, err := boundary.NewClient(&cfg)
	if err != nil {
		return nil, err
	}

	c := &boundaryClient{
		Client: client,
		config: config,
	}

	if err := c.authenticate(); err != nil {
		return nil, fmt.Errorf("unable to authenticate new client: %w", err)
	}

	return c, nil
}

// authenticate authenticates the client with the provided configuration. The
// client and configuration must not be nil.  The client's token expiration time
// and token are set as a result of a successful authentication.
func (c *boundaryClient) authenticate() error {
	switch {
	case c.Client == nil:
		return errors.New("client was nil")
	case c.config == nil:
		return errors.New("client configuration was nil")
	}
	credentials := map[string]interface{}{
		loginNameAttribName: c.config.LoginName,
		passwordAttribName:  c.config.Password,
	}

	amClient := authmethods.NewClient(c.Client)

	authenticationResult, err := amClient.Authenticate(context.Background(), c.config.AuthMethodId, "login", credentials)
	if err != nil {
		return err
	}

	c.Client.SetToken(fmt.Sprint(authenticationResult.Attributes[tokenAttribName]))

	rawExp, ok := authenticationResult.Attributes[tokenExpirationTimeAttribName]
	if !ok {
		return errors.New("expiration_time was not defined")
	}
	timeString, ok := rawExp.(string)
	if !ok {
		return errors.New("expiration_time was not a string")
	}
	parsedTime, err := time.Parse(time.RFC3339, timeString)
	if err != nil {
		return err
	}
	c.tokenExp = parsedTime

	return nil
}

// tokenIsExpired returns true if the client's token has expired.  We provide a
// 1 minute buffer to ensure that the token is not expired when we use it.
func (c *boundaryClient) tokenIsExpired() bool {
	return time.Now().After(c.tokenExp.Add(-1 * time.Minute))
}
