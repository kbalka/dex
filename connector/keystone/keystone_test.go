package keystone

import (
	"testing"
	"github.com/dexidp/dex/connector"

	"fmt"
	"os"
	"net/http"

	"golang.org/x/net/context"
	"bytes"
	"encoding/json"
	"io/ioutil"
	"github.com/stretchr/testify/assert"
)

const (
	adminUser = "demo"
	adminPass = "DEMO_PASS"
	invalidPass = "WRONG_PASS"

	testUser = "test_user"
	testPass = "test_pass"
	testEmail = "test@example.com"
	testGroup = "test_group"
	domain = "default"
)

var (
	keystoneURL = ""
	keystoneAdminURL = ""
	authTokenURL = ""
	usersURL = ""
	groupsURL = ""
)


type createUserRequest struct {
	CreateUser createUserForm `json:"user"`
}

type createUserForm struct {
	Name     string   `json:"name"`
	Email    string   `json:"email"`
	Enabled  bool     `json:"enabled"`
	Password string   `json:"password"`
	Roles    []string `json:"roles"`
}

type userResponse struct {
	User createUserResponse `json:"user"`
}

type createUserResponse struct {
	Username string   `json:"username"`
	Name     string   `json:"name"`
	Roles    []string `json:"roles"`
	Enabled  bool     `json:"enabled"`
	ID       string   `json:"id"`
	Email    string   `json:"email"`
}

type createKeystoneGroup struct {
	Group createGroupForm `json:"group"`
}

type createGroupForm struct {
	Description string `json:"description"`
	Name        string `json:"name"`
}

type groupID struct {
	Group groupIDForm `json:"group"`
}

type groupIDForm struct {
	ID string `json:"id"`
}

func getAdminToken(t *testing.T, adminName, adminPass string) (token, id string, err error) {
	t.Helper()
	client := &http.Client{}

	jsonData := loginRequestData{
		auth: auth{
			Identity: identity{
				Methods:[]string{"password"},
				Password: password{
					User: user{
						Name:     adminName,
						Domain:   Domain{ID: "default"},
						Password: adminPass,
					},
				},
			},
		},
	}

	body, err := json.Marshal(jsonData)

	if err != nil {
		return "", "", err
	}

	req, err := http.NewRequest("POST", authTokenURL, bytes.NewBuffer(body))

	if err != nil {
		t.Fatalf("keystone: failed to obtain admin token: %v\n", err)
		return "", "", err
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}

	token = resp.Header.Get("X-Subject-Token")

	data, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return "", "", err
	}

	var tokenResponse = new(tokenResponse)
	err = json.Unmarshal(data, &tokenResponse)
	if err != nil {
		return "", "", err
	}
	return token, tokenResponse.Token.User.ID, nil
}

func createUser(t *testing.T, token, userName, userEmail, userPass string) (string, error){
	t.Helper()
	client := &http.Client{}

	createUserData := createUserRequest{
		CreateUser: createUserForm{
			Name:     userName,
			Email:    userEmail,
			Enabled:  true,
			Password: userPass,
			Roles:    []string{"admin"},
		},
	}

	body, err := json.Marshal(createUserData)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", usersURL, bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Auth-Token", token)
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	data, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return "", err
	}
	var userResponse = new(userResponse)
	err = json.Unmarshal(data, &userResponse)
	if err != nil {
		return "", err
	}

	return userResponse.User.ID, nil
}

// delete group or user
func delete(t *testing.T, token, id, uri string) (error) {
	t.Helper()
	client := &http.Client{}

	deleteURI := uri + id
	req, err := http.NewRequest("DELETE", deleteURI, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
		return err
	}
	req.Header.Set("X-Auth-Token", token)
	client.Do(req)
	return nil
}

func createGroup(t *testing.T, token, description, name string) (string, error) {
	t.Helper()
	client := &http.Client{}

	createGroupData := createKeystoneGroup{
		createGroupForm{
			Description: description,
			Name: name,
		},
	}

	body, err := json.Marshal(createGroupData)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", groupsURL, bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Auth-Token", token)
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	data, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return "", err
	}

	var groupResponse = new(groupID)
	err = json.Unmarshal(data, &groupResponse)
	if err != nil {
		return "", err
	}

	return groupResponse.Group.ID, nil
}

func addUserToGroup(t *testing.T, token, groupID, userID string) error {
	t.Helper()
	uri := groupsURL + groupID + "/users/" + userID
	client := &http.Client{}
	req, err := http.NewRequest("PUT", uri, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Auth-Token", token)
	client.Do(req)
	return nil
}

func TestIncorrectCredentialsLogin(t *testing.T) {
	c := keystoneConnector{KeystoneHost: keystoneURL, Domain: domain,
		KeystoneUsername: adminUser, KeystonePassword: adminPass}
	s := connector.Scopes{OfflineAccess: true, Groups: true}
	_, validPW, _ := c.Login(context.Background(), s, adminUser, invalidPass)

	if validPW {
		t.Fail()
	}
}

func TestValidUserLogin(t *testing.T) {
	token, _, _ := getAdminToken(t, adminUser, adminPass)
	userID, _ := createUser(t, token, testUser, testEmail, testPass)
	c := keystoneConnector{KeystoneHost: keystoneURL, Domain: domain,
		KeystoneUsername: adminUser, KeystonePassword: adminPass}
	s := connector.Scopes{OfflineAccess: true, Groups: true}
	identity, validPW, _ := c.Login(context.Background(), s, testUser, testPass)
	t.Log(identity)
	if !validPW {
		t.Fail()
	}
	delete(t, token, userID, usersURL)
}

func TestUseRefreshToken(t *testing.T) {
	token, adminID, _ := getAdminToken(t, adminUser, adminPass)
	groupID, _ := createGroup(t, token, "Test group description", testGroup)
	addUserToGroup(t, token, groupID, adminID)

	c := keystoneConnector{KeystoneHost: keystoneURL, Domain: domain,
		KeystoneUsername: adminUser, KeystonePassword: adminPass}
	s := connector.Scopes{OfflineAccess: true, Groups: true}

	identityLogin, _, _ := c.Login(context.Background(), s, adminUser, adminPass)
	identityRefresh, _ := c.Refresh(context.Background(), s, identityLogin)

	delete(t, token, groupID, groupsURL)

	assert.Equal(t, 1, len(identityRefresh.Groups))
	assert.Equal(t, testGroup, string(identityRefresh.Groups[0]))
}

func TestUseRefreshTokenUserDeleted(t *testing.T){
	token, _, _ := getAdminToken(t, adminUser, adminPass)
	userID, _ := createUser(t, token, testUser, testEmail, testPass)

	c := keystoneConnector{KeystoneHost: keystoneURL, Domain: domain,
		KeystoneUsername: adminUser, KeystonePassword: adminPass}
	s := connector.Scopes{OfflineAccess: true, Groups: true}

	identityLogin, _, _ := c.Login(context.Background(), s, testUser, testPass)
	c.Refresh(context.Background(), s, identityLogin)

	delete(t, token, userID, usersURL)
	_, response := c.Refresh(context.Background(), s, identityLogin)

	assert.Contains(t, response.Error(), "does not exist")
}

func TestUseRefreshTokenGroupsChanged(t *testing.T){
	token, _, _ := getAdminToken(t, adminUser, adminPass)
	userID, _ := createUser(t, token, testUser, testEmail, testPass)

	c := keystoneConnector{KeystoneHost: keystoneURL, Domain: domain,
		KeystoneUsername: adminUser, KeystonePassword: adminPass}
	s := connector.Scopes{OfflineAccess: true, Groups: true}

	identityLogin, _, _ := c.Login(context.Background(), s, testUser, testPass)
	identityRefresh, _ := c.Refresh(context.Background(), s, identityLogin)

	assert.Equal(t, 0, len(identityRefresh.Groups))

	groupID, _ := createGroup(t, token, "Test group description", testGroup)
	addUserToGroup(t, token, groupID, userID)

	identityRefresh, _ = c.Refresh(context.Background(), s, identityLogin)

	delete(t, token, groupID, groupsURL)
	delete(t, token, userID, usersURL)

	assert.Equal(t, 1, len(identityRefresh.Groups))
}

func TestMain(m *testing.M) {
	keystoneURLEnv := "DEX_KEYSTONE_URL"
	keystoneAdminURLEnv := "DEX_KEYSTONE_ADMIN_URL"
	keystoneURL = os.Getenv(keystoneURLEnv)
	if keystoneURL == "" {
		fmt.Printf("variable %q not set, skipping keystone connector tests\n", keystoneURLEnv)
		return
	}
	keystoneAdminURL := os.Getenv(keystoneAdminURLEnv)
	if keystoneAdminURL == "" {
		fmt.Printf("variable %q not set, skipping keystone connector tests\n", keystoneAdminURLEnv)
		return
	}
	authTokenURL = keystoneURL + "/v3/auth/tokens/"
	fmt.Printf("Auth token url %q\n", authTokenURL)
	fmt.Printf("Keystone URL %q\n", keystoneURL)
	usersURL = keystoneAdminURL + "/v3/users/"
	groupsURL = keystoneAdminURL + "/v3/groups/"
	// run all tests
	m.Run()
}
