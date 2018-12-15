package keystone

import (
	"github.com/sirupsen/logrus"
)

const exposedKeystonePort = "5000"
const exposedKeystonePortAdmin = "35357"

const keystoneHost = "http://localhost:"
const keystoneURL = keystoneHost + exposedKeystonePort
const keystoneAdminURL = keystoneHost + exposedKeystonePortAdmin
const authTokenURL = keystoneURL + "/v3/auth/tokens/"
const usersURL = keystoneAdminURL + "/v3/users/"
const groupsURL = keystoneAdminURL + "/v3/groups/"

type keystoneConnector struct {
	Domain           string
	KeystoneHost     string
	KeystoneUsername string
	KeystonePassword string
	Logger           logrus.FieldLogger
}

type userKeystone struct {
	Domain domainKeystone `json:"domain"`
	ID     string         `json:"id"`
	Name   string         `json:"name"`
}

type domainKeystone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Config holds the configuration parameters for Keystone connector.
// An example config:
//	connectors:
//		type: keystone
//		id: keystone
//		name: Keystone
//		config:
//			keystoneHost: http://example:5000
//			domain: default
//      keystoneUsername: demo
//      keystonePassword: DEMO_PASS
type Config struct {
	Domain           string `json:"domain"`
	KeystoneHost     string `json:"keystoneHost"`
	KeystoneUsername string `json:"keystoneUsername"`
	KeystonePassword string `json:"keystonePassword"`
}

type loginRequestData struct {
	auth `json:"auth"`
}

type auth struct {
	Identity identity `json:"identity"`
}

type identity struct {
	Methods  []string `json:"methods"`
	Password password `json:"password"`
}

type password struct {
	User user `json:"user"`
}

type user struct {
	Name     string `json:"name"`
	Domain   Domain `json:"domain"`
	Password string `json:"password"`
}

// Domain struct holds an ID of domain
type Domain struct {
	ID string `json:"id"`
}

type token struct {
	IssuedAt  string                 `json:"issued_at"`
	Extras    map[string]interface{} `json:"extras"`
	Methods   []string               `json:"methods"`
	ExpiresAt string                 `json:"expires_at"`
	User      userKeystone           `json:"user"`
}

type tokenResponse struct {
	Token token `json:"token"`
}

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

type links struct {
	Self     string `json:"self"`
	Previous string `json:"previous"`
	Next     string `json:"next"`
}

type group struct {
	DomainID    string `json:"domain_id`
	Description string `json:"description"`
	ID          string `json:"id"`
	Links       links  `json:"links"`
	Name        string `json:"name"`
}

type groupsResponse struct {
	Links  links   `json:"links"`
	Groups []group `json:"groups"`
}
