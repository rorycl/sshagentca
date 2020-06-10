package util

import (
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	yaml "gopkg.in/yaml.v3"
	"io/ioutil"
)

const maxmins uint32 = 24 * 60 // limit max validity to 24 hours

// Restrict the certificate extensions to those commonly supported as
// defined at https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
// Note that the extensions each (only) use an empty string for their
// value
var permittedExtensions = map[string]string{
	// "no-presence-required": "", // only U2F/Fido
	"permit-agent-forwarding": "",
	"permit-port-forwarding":  "",
	"permit-pty":              "",
	"permit-X11-forwarding":   "",
	"permit-user-rc":          "",
}

// UserPrincipals are configured in the yaml settings file to have
// certificates created for the stated Principals given access to the
// sshagentca server with SSHPublicKey. SSH Key fingerprints are used
// for lookups as these are more convenient for logging. See
// settings.example.yaml for the example settings file.
type UserPrincipals struct {
	Name        string
	Principals  []string
	PublicKey   ssh.PublicKey
	Fingerprint string
}

func (up *UserPrincipals) UnmarshalYAML(value *yaml.Node) (err error) {

	// auxilliary unmarshall struct
	type AuxUserPrincipals struct {
		Name       string   `yaml:"name"`
		Principals []string `yaml:"principals"`
		PublicKey  string   `yaml:"sshpublickey"`
	}

	var aup AuxUserPrincipals
	err = value.Decode(&aup)
	if err != nil {
		return fmt.Errorf("Yaml parsing error: %v", err)
	}

	pubKey, err := LoadPublicKeyBytes([]byte(aup.PublicKey))
	if err != nil {
		return fmt.Errorf("yaml error: user %s has an invalid public key: %w", aup.Name, err)
	}
	fingerprint := string(ssh.FingerprintSHA256(pubKey))

	*up = UserPrincipals{
		Name:        aup.Name,
		Principals:  aup.Principals,
		PublicKey:   pubKey,
		Fingerprint: fingerprint,
	}

	return err
}

// main yaml settings structure, which incorporates a slice of
// UserPrincipals together with general server settings
type Settings struct {
	Validity           uint32            `yaml:"validity"`
	Organisation       string            `yaml:"organisation"`
	Banner             string            `yaml:"banner"`
	Extensions         map[string]string `yaml:"extensions,flow"`
	Users              []*UserPrincipals `yaml:"user_principals"`
	usersByFingerprint map[string]*UserPrincipals
}

// Load a settings yaml file into a Settings struct
func SettingsLoad(yamlFilePath string) (Settings, error) {

	var s = Settings{}

	filer, err := ioutil.ReadFile(yamlFilePath)
	if err != nil {
		return s, err
	}

	err = yaml.Unmarshal(filer, &s)
	if err != nil {
		return s, err
	}

	if len(s.Users) == 0 {
		return s, errors.New("no valid users found in yaml file")
	}

	// run validation
	err = s.validate()
	if err != nil {
		return s, err
	}

	return s, nil
}

// Extract a user's UserPrincipals struct by public key fingerprint
func (s *Settings) UserByFingerprint(fp string) (*UserPrincipals, error) {
	var up = &UserPrincipals{}
	up, ok := s.usersByFingerprint[fp]
	if !ok {
		return up, errors.New(fmt.Sprintf("user for public key %s not found", fp))
	}
	return up, nil
}

// build map by key fingerprint
func (s *Settings) buildFingerprintMap() error {
	s.usersByFingerprint = map[string]*UserPrincipals{}
	for _, u := range s.Users {
		if _, ok := s.usersByFingerprint[u.Fingerprint]; ok {
			return errors.New(fmt.Sprintf("user %s key already exists", u.Name))
		}
		s.usersByFingerprint[u.Fingerprint] = u
	}
	return nil
}

// Validate the certificate extensions, validity period and user records
func (s *Settings) validate() error {

	// build map of keys by publickey
	err := s.buildFingerprintMap()
	if err != nil {
		return err
	}

	// check validity period
	if !(0 < s.Validity) {
		return errors.New("validity must be >0")
	} else if s.Validity > maxmins {
		return errors.New(fmt.Sprintf("validity must be <%d", maxmins))
	}

	// check extensions meet permittedExtensions
	for k, v := range s.Extensions {
		val, ok := permittedExtensions[k]
		if !ok {
			return errors.New(fmt.Sprintf("extension %s not permitted", k))
		}
		if v != val {
			return errors.New(fmt.Sprintf("value '%s' for key %s not permitted, expected %s", val, k, v))
		}
	}

	// check users
	for _, v := range s.Users {
		if v.Name == "" {
			return errors.New("user provided with empty name")
		} else if len(v.Principals) == 0 {
			return errors.New(fmt.Sprintf("user %s provided with no principals", v.Name))
		} else if v.PublicKey == nil {
			return errors.New(fmt.Sprintf("user %s has no publickey", v.Name))
		}
	}

	// check all users have a public keys
	for fp, user := range s.usersByFingerprint {
		if user.PublicKey == nil {
			return errors.New(fmt.Sprintf("user %s has empty public key", user.Name))
		}
		// some mangling has happened to a key?
		if fp != string(ssh.FingerprintSHA256(user.PublicKey)) {
			return errors.New(fmt.Sprintf("user %s public key mismatch", user.Name))
		}
	}

	return nil
}
