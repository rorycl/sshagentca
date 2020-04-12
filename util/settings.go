package util

import (
	"errors"
	"fmt"
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

type UserPrincipals struct {
	Name        string   `yaml:"name"`
	// ssh.FingerprintSHA256
	Fingerprint string   `yaml:"fingerprint"`
	Principals  []string `yaml:"principals,flow"`
}

type Settings struct {
	Validity           uint32                    `yaml:"validity"`
	Organisation       string                    `yaml:"organisation"`
	Banner             string                    `yaml:"banner"`
	Extensions         map[string]string         `yaml:"extensions,flow"`
	Users              []UserPrincipals          `yaml:"user_principals"`
    usersByFingerprint map[string]UserPrincipals
}


// Load a settings yaml file into a Settings struct
func SettingsLoad(filepath string) (s Settings, err error) {

	filer, err := ioutil.ReadFile(filepath)
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

	err = s.Validate()
	if err != nil {
		return s, err
	}

	err = s.buildFPMap()
	if err != nil {
		return s, err
	}

	return s, nil
}

// Extract a user's UserPrincipals struct by fingerprint
func (s *Settings) UserByFingerprint(fp string) (UserPrincipals, error) {
	var up = UserPrincipals{}
	up, ok := s.usersByFingerprint[fp]
	if !ok {
		return up, errors.New(fmt.Sprintf("user for fingerprint %s not found", fp))
	}
	return up, nil
}

// build map by fingerprint
func (s *Settings) buildFPMap () error {
	s.usersByFingerprint = map[string]UserPrincipals{}
	for _, u := range s.Users {
		if u.Fingerprint != "" {
			s.usersByFingerprint[u.Fingerprint] = u
		}
	}
	return nil
}

// Validate the certificate extensions, validity period and user records
func (s *Settings) Validate() error {

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
		} else if v.Fingerprint[:7] != "SHA256:" {
			return errors.New(fmt.Sprintf("user %s fingerprint does not start with SHA256:", v.Name))
		} else if len(v.Fingerprint) != 50 {
			return errors.New(fmt.Sprintf("user %s fingerprint unexpected length", v.Name))
		}
	}

	return nil

}
