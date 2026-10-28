package console

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	RoleReviewer = "reviewer" // read sample text, add reviews
	RoleAdmin    = "admin"    // delete samples; does not imply reviewer
	sharedActor  = "shared-token"
)

// Account is a named console identity. Its token is 32 random bytes, so a SHA-256 digest is
// enough to store it (a slow password hash only helps low-entropy secrets).
type Account struct {
	Name        string   `yaml:"name"`
	TokenSHA256 string   `yaml:"token_sha256"`
	Roles       []string `yaml:"roles"`
}

var accountName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)

func (a Account) validate() error {
	if !accountName.MatchString(a.Name) || a.Name == sharedActor {
		return fmt.Errorf("account name %q must match %s and not be %q", a.Name, accountName, sharedActor)
	}
	if d, err := hex.DecodeString(a.TokenSHA256); err != nil || len(d) != sha256.Size {
		return fmt.Errorf("account %s: token_sha256 must be 64 hex characters", a.Name)
	}
	for _, r := range a.Roles {
		if r != RoleReviewer && r != RoleAdmin {
			return fmt.Errorf("account %s: unknown role %q", a.Name, r)
		}
	}
	return nil
}

// LoadAccounts reads the accounts file written from riskguard -new-account output. Removing an
// entry and restarting revokes it.
func LoadAccounts(path string) ([]Account, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f struct {
		Accounts []Account `yaml:"accounts"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	seen := map[string]bool{}
	for _, a := range f.Accounts {
		if err := a.validate(); err != nil {
			return nil, err
		}
		if seen[a.Name] || seen[a.TokenSHA256] {
			return nil, errors.New("duplicate account name or token")
		}
		seen[a.Name], seen[a.TokenSHA256] = true, true
	}
	return f.Accounts, nil
}

// NewAccount returns a fresh token (shown once) and the accounts-file entry holding its digest.
func NewAccount(name string, roles []string) (token, entry string, err error) {
	var b [32]byte
	rand.Read(b[:])
	token = hex.EncodeToString(b[:])
	sum := sha256.Sum256([]byte(token))
	a := Account{Name: name, TokenSHA256: hex.EncodeToString(sum[:]), Roles: roles}
	if err := a.validate(); err != nil {
		return "", "", err
	}
	out, _ := yaml.Marshal([]Account{a})
	return token, string(out), nil
}

type session struct {
	exp   time.Time
	actor string
	roles []string
}

func (s session) has(role string) bool { return slices.Contains(s.roles, role) }
