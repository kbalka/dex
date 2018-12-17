// Package keystone provides authentication strategy using Keystone.
package keystone

import (
	"context"
	"fmt"
	"github.com/dexidp/dex/connector"
	"github.com/sirupsen/logrus"
	"encoding/json"
	"net/http"
	"bytes"
	"io/ioutil"
)

var (
	_ connector.PasswordConnector = &keystoneConnector{}
	_ connector.RefreshConnector = &keystoneConnector{}
)

// Open returns an authentication strategy using Keystone.
func (c *Config) Open(id string, logger logrus.FieldLogger) (connector.Connector, error) {
	return &keystoneConnector{c.Domain, c.KeystoneHost,
		c.KeystoneUsername, c.KeystonePassword, logger}, nil
}

func (p keystoneConnector) Close() error { return nil }

func (p keystoneConnector) Login(ctx context.Context, s connector.Scopes, username, password string) (
	identity connector.Identity, validPassword bool, err error) {
	resp, err := p.getTokenResponse(ctx, &http.Client{}, username, password)

	if err != nil {
		return identity, false, fmt.Errorf("keystone: error %v\n", err)
	}

	// Providing wrong password or wrong keystone URI throws error
	if resp.StatusCode == 201 {
		token := resp.Header["X-Subject-Token"][0]
		data, err := ioutil.ReadAll(resp.Body)
		defer resp.Body.Close()

		if err != nil {
			return identity, false, err
		}

		var tokenResponse = new(tokenResponse)
		err = json.Unmarshal(data, &tokenResponse)

		if err != nil {
			return identity, false, fmt.Errorf("keystone: invalid token response: %v\n", err)
		}
		groups, err := p.getUserGroups(tokenResponse.Token.User.ID, token)

		if err != nil {
			return identity, false, err
		}

		identity.Username =	username
		identity.UserID = tokenResponse.Token.User.ID
		identity.Groups = groups
		return identity, true, nil

	} else {
		data, err := ioutil.ReadAll(resp.Body)
		defer resp.Body.Close()

		if err != nil {
			return identity, false, err
		}

		fmt.Println(string(data))
		return identity, false, nil
	}
	return identity, false, nil
}

func (p keystoneConnector) Prompt() string { return "username" }

func (p keystoneConnector) Refresh(
	ctx context.Context, s connector.Scopes, identity connector.Identity) (connector.Identity, error) {

	token, err := p.getAdminToken()
	if err != nil {
		return identity, fmt.Errorf("keystone: failed to obtain admin token: %v\n", err)
	}

	ok, err := p.checkIfUserExists(identity.UserID, token)
	if err != nil {
		return identity, err
	}
	if !ok {
		return identity, fmt.Errorf("keystone: user %q does not exist\n", identity.UserID)
	}

	groups, err := p.getUserGroups(identity.UserID, token)
	if err != nil {
		return identity, err
	}

	identity.Groups = groups
	fmt.Printf("identity data after use of refresh token: %v\n", identity)
	return identity, nil
}


func (p keystoneConnector) getTokenResponse(ctx context.Context, client *http.Client, username, pass string) (response *http.Response, err error) {
	jsonData := loginRequestData{
		auth: auth{
			Identity: identity{
				Methods:[]string{"password"},
				Password: password{
					User: user{
						Name:     username,
						Domain:   Domain{ID:p.Domain},
						Password: pass,
					},
				},
			},
		},
	}
	jsonValue, err := json.Marshal(jsonData)

	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", authTokenURL, bytes.NewBuffer(jsonValue))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctx)

	return client.Do(req)
}

func (p keystoneConnector) getAdminToken()(string, error) {
	ctx := context.Background()
	response, err := p.getTokenResponse(ctx, &http.Client{}, p.KeystoneUsername, p.KeystonePassword)
	if err != nil {
		return "", err
	}
	token := response.Header["X-Subject-Token"][0]
	return token, nil
}

func (p keystoneConnector) checkIfUserExists(userID string, token string) (bool, error) {
	userURL := usersURL + userID
	client := &http.Client{}
	req, err := http.NewRequest("GET", userURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-Auth-Token", token)
	resp, err := client.Do(req)

	if err != nil {
		return false, err
	}

	if resp.StatusCode == 200 {
		return true, nil
	}
	return false, err
}

func (p keystoneConnector) getUserGroups(userID string, token string) ([]string, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", groupsURL, nil)

	req.Header.Set("X-Auth-Token", token)
	resp, err :=  client.Do(req)
	if err != nil {
		fmt.Printf("keystone: error while fetching user %q groups\n", userID)
		return nil, err
	}

	data, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
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
