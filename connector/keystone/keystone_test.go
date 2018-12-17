package keystone

import (
	"github.com/dexidp/dex/connector"
	"testing"

	"fmt"
	"net/http"
	"os"

	"bytes"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/context"
	"io/ioutil"
)

const dockerCliVersion = "1.37"

const adminUser = "demo"
const adminPass = "DEMO_PASS"
const invalidPass = "WRONG_PASS"

const testUser = "test_user"
const testPass = "test_pass"
const testEmail = "test@example.com"
const testGroup = "test_group"
const domain = "default"

var keystoneURL = ""
var keystoneAdminURL = ""
var authTokenURL = ""
var usersURL = ""
var groupsURL = ""

func getAdminToken(adminName, adminPass string) (token, id string) {
	client := &http.Client{}

	jsonData := loginRequestData{
		auth: auth{
			Identity: identity{
				Methods: []string{"password"},
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

	body, _ := json.Marshal(jsonData)

	req, _ := http.NewRequest("POST", authTokenURL, bytes.NewBuffer(body))

	req.Header.Set("Content-Type", "application/json")
	resp, _ := client.Do(req)

	token = resp.Header["X-Subject-Token"][0]

	data, _ := ioutil.ReadAll(resp.Body)
	var tokenResponse = new(tokenResponse)
	err := json.Unmarshal(data, &tokenResponse)
	if err != nil {
		fmt.Println(err)
	}
	return token, tokenResponse.Token.User.ID
}

func createUser(token, userName, userEmail, userPass string) string {
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

	body, _ := json.Marshal(createUserData)

	req, _ := http.NewRequest("POST", usersURL, bytes.NewBuffer(body))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Add("Content-Type", "application/json")
	resp, _ := client.Do(req)

	data, _ := ioutil.ReadAll(resp.Body)
	var userResponse = new(userResponse)
	err := json.Unmarshal(data, &userResponse)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(userResponse.User.ID)
	return userResponse.User.ID

}

// delete group or user
func delete(token, id, uri string) {
	client := &http.Client{}

	deleteURI := uri + id
	req, _ := http.NewRequest("DELETE", deleteURI, nil)
	req.Header.Set("X-Auth-Token", token)
	client.Do(req)
}

func createGroup(token, description, name string) string {
	client := &http.Client{}

	createGroupData := createKeystoneGroup{
		createGroupForm{
			Description: description,
			Name:        name,
		},
	}

	body, _ := json.Marshal(createGroupData)

	req, _ := http.NewRequest("POST", groupsURL, bytes.NewBuffer(body))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Add("Content-Type", "application/json")
	resp, _ := client.Do(req)
	data, _ := ioutil.ReadAll(resp.Body)

	var groupResponse = new(groupID)
	err := json.Unmarshal(data, &groupResponse)
	if err != nil {
		fmt.Println(err)
	}

	return groupResponse.Group.ID
}

func addUserToGroup(token, groupID, userID string) {
	uri := groupsURL + groupID + "/users/" + userID
	client := &http.Client{}
	req, _ := http.NewRequest("PUT", uri, nil)
	req.Header.Set("X-Auth-Token", token)
	client.Do(req)
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
	token, _ := getAdminToken(adminUser, adminPass)
	userID := createUser(token, testUser, testEmail, testPass)
	c := keystoneConnector{KeystoneHost: keystoneURL, Domain: domain,
		KeystoneUsername: adminUser, KeystonePassword: adminPass}
	s := connector.Scopes{OfflineAccess: true, Groups: true}
	identity, validPW, _ := c.Login(context.Background(), s, testUser, testPass)
	fmt.Println(identity)
	if !validPW {
		t.Fail()
	}
	delete(token, userID, usersURL)
}

func TestUseRefreshToken(t *testing.T) {
	token, adminID := getAdminToken(adminUser, adminPass)
	groupID := createGroup(token, "Test group description", testGroup)
	addUserToGroup(token, groupID, adminID)

	c := keystoneConnector{KeystoneHost: keystoneURL, Domain: domain,
		KeystoneUsername: adminUser, KeystonePassword: adminPass}
	s := connector.Scopes{OfflineAccess: true, Groups: true}

	identityLogin, _, _ := c.Login(context.Background(), s, adminUser, adminPass)
	identityRefresh, _ := c.Refresh(context.Background(), s, identityLogin)

	delete(token, groupID, groupsURL)

	assert.Equal(t, 1, len(identityRefresh.Groups))
	assert.Equal(t, testGroup, string(identityRefresh.Groups[0]))
}

func TestUseRefreshTokenUserDeleted(t *testing.T) {
	token, _ := getAdminToken(adminUser, adminPass)
	userID := createUser(token, testUser, testEmail, testPass)

	c := keystoneConnector{KeystoneHost: keystoneURL, Domain: domain,
		KeystoneUsername: adminUser, KeystonePassword: adminPass}
	s := connector.Scopes{OfflineAccess: true, Groups: true}

	identityLogin, _, _ := c.Login(context.Background(), s, testUser, testPass)
	c.Refresh(context.Background(), s, identityLogin)

	delete(token, userID, usersURL)
	_, response := c.Refresh(context.Background(), s, identityLogin)

	assert.Contains(t, response.Error(), "does not exist")
}

func TestUseRefreshTokenGroupsChanged(t *testing.T) {
	token, _ := getAdminToken(adminUser, adminPass)
	userID := createUser(token, testUser, testEmail, testPass)

	c := keystoneConnector{KeystoneHost: keystoneURL, Domain: domain,
		KeystoneUsername: adminUser, KeystonePassword: adminPass}
	s := connector.Scopes{OfflineAccess: true, Groups: true}

	identityLogin, _, _ := c.Login(context.Background(), s, testUser, testPass)
	identityRefresh, _ := c.Refresh(context.Background(), s, identityLogin)

	assert.Equal(t, 0, len(identityRefresh.Groups))

	groupID := createGroup(token, "Test group description", testGroup)
	addUserToGroup(token, groupID, userID)

	identityRefresh, _ = c.Refresh(context.Background(), s, identityLogin)

	delete(token, groupID, groupsURL)
	delete(token, userID, usersURL)

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
