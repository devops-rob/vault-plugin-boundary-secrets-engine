package boundarysecrets

import (
	"context"
	"errors"
	"fmt"
	boundary "github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
)

type boundaryClient struct {
	*boundary.Client
}

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

	credentials := map[string]interface{}{
		"login_name": config.LoginName,
		"password":   config.Password,
	}

	amClient := authmethods.NewClient(client)

	authenticationResult, err := amClient.Authenticate(context.Background(), config.AuthMethodId, "login", credentials)
	if err != nil {
		return nil, err
	}

	client.SetToken(fmt.Sprint(authenticationResult.Attributes["token"]))

	return &boundaryClient{client}, nil
}
