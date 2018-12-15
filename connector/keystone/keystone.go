// Package keystone provides authentication strategy using Keystone.
package keystone

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/dexidp/dex/connector"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
)

var (
	_ connector.PasswordConnector = &keystoneConnector{}
	_ connector.RefreshConnector  = &keystoneConnector{}
)

// Open returns an authentication strategy using Keystone.
func (c *Config) Open(id string, logger logrus.FieldLogger) (connector.Connector, error) {
	return &keystoneConnector{c.Domain, c.KeystoneHost,
		c.KeystoneUsername, c.KeystonePassword, logger}, nil
}

func (p keystoneConnector) Close() error { return nil }

func (p keystoneConnector) Login(ctx context.Context, s connector.Scopes, username, password string) (
	identity connector.Identity, validPassword bool, err error) {
	response, err := p.getTokenResponse(username, password)

	// Providing wrong password or wrong keystone URI throws error
	if err == nil && response.StatusCode == 201 {
		token := response.Header["X-Subject-Token"][0]
		data, _ := ioutil.ReadAll(response.Body)

		var tokenResponse = new(tokenResponse)
		err := json.Unmarshal(data, &tokenResponse)

		if err != nil {
			fmt.Printf("keystone: invalid token response: %v", err)
			return identity, false, err
		}
		groups, err := p.getUserGroups(tokenResponse.Token.User.ID, token)

		if err != nil {
			return identity, false, err
		}

		identity.Username = username
		identity.UserID = tokenResponse.Token.User.ID
		identity.Groups = groups
		return identity, true, nil

	} else if err != nil {
		fmt.Printf("keystone: error %v", err)
		return identity, false, err

	} else {
		data, _ := ioutil.ReadAll(response.Body)
		fmt.Println(string(data))
		return identity, false, err
	}
	return identity, false, nil
}

func (p keystoneConnector) Prompt() string { return "username" }

func (p keystoneConnector) Refresh(
	ctx context.Context, s connector.Scopes, identity connector.Identity) (connector.Identity, error) {

	token, err := p.getAdminToken()

	if err != nil {
		fmt.Printf("keystone: failed to obtain admin token")
		return identity, err
	}

	ok := p.checkIfUserExists(identity.UserID, token)
	if !ok {
		fmt.Printf("keystone: user %q does not exist\n", identity.UserID)
		return identity, fmt.Errorf("keystone: user %q does not exist", identity.UserID)
	}

	groups, err := p.getUserGroups(identity.UserID, token)
	if err != nil {
		fmt.Printf("keystone: Failed to fetch user %q groups", identity.UserID)
		return identity, fmt.Errorf("keystone: failed to fetch user %q groups", identity.UserID)
	}

	identity.Groups = groups
	fmt.Printf("identity data after use of refresh token: %v", identity)
	return identity, nil
}

func (p keystoneConnector) getTokenResponse(username, pass string) (response *http.Response, err error) {
	jsonData := loginRequestData{
		auth: auth{
			Identity: identity{
				Methods: []string{"password"},
				Password: password{
					User: user{
						Name:     username,
						Domain:   Domain{ID: p.Domain},
						Password: pass,
					},
				},
			},
		},
	}
	jsonValue, _ := json.Marshal(jsonData)
	return http.Post(authTokenURL, "application/json", bytes.NewBuffer(jsonValue))
}

func (p keystoneConnector) getAdminToken() (string, error) {
	response, err := p.getTokenResponse(p.KeystoneUsername, p.KeystonePassword)
	if err != nil {
		return "", err
	}
	token := response.Header["X-Subject-Token"][0]
	return token, nil
}

func (p keystoneConnector) checkIfUserExists(userID string, token string) bool {
	userURL := usersURL + userID
	client := &http.Client{}
	req, _ := http.NewRequest("GET", userURL, nil)
	req.Header.Set("X-Auth-Token", token)
	response, err := client.Do(req)
	if err == nil && response.StatusCode == 200 {
		return true
	}
	return false
}

func (p keystoneConnector) getUserGroups(userID string, token string) ([]string, error) {
	client := &http.Client{}
	req, _ := http.NewRequest("GET", groupsURL, nil)
	req.Header.Set("X-Auth-Token", token)
	response, err := client.Do(req)

	if err != nil {
		fmt.Printf("keystone: error while fetching user %q groups\n", userID)
		return nil, err
	}
	data, _ := ioutil.ReadAll(response.Body)
	var groupsResponse = new(groupsResponse)
	err = json.Unmarshal(data, &groupsResponse)
	if err != nil {
		return nil, err
	}
	groups := []string{}
	for _, group := range groupsResponse.Groups {
		groups = append(groups, group.Name)
	}
	return groups, nil
}
