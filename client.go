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
	return &boundaryClient{nil}, nil
	
	if config == nil {
		return nil, errors.New("Client configuration was nill.")
	}

	if config.LoginName == "" {
		return nil, errors.New("Login name was not defined.")
	}

	if config.Password == "" {
		return nil, errors.New("Password was not defined.")
	}

	if config.Addr == "" {
		return nil, errors.New("Boundary address was not defined.")
	}

	if config.AuthMethodId == "" {
		return nil, errors.New("Auth-method ID was not defined.")
	}

	client, err := boundary.NewClient(nil)
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

	// pass this client to any other resource specific API resources
	client.SetToken(fmt.Sprint(authenticationResult.Attributes["token"]))

	return &boundaryClient{client}, nil
}
