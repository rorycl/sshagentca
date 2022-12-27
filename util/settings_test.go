package util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestSettingsParse(t *testing.T) {
	settings, err := SettingsLoad("../settings.example.yaml")
	if err != nil {
		t.Errorf("Could not parse yaml %v", err)
	}
	t.Logf("Settings : %+v", settings)
}

func TestSettingsParse2(t *testing.T) {
	settings, err := SettingsLoad("../settings.example.yaml")
	if err != nil {
		t.Errorf("Could not parse yaml %v", err)
	}
	settings.Validity = 0
	err = settings.validate()
	t.Logf("Error (expected): %s", err)
	if err == nil {
		t.Errorf("Invalid validity did not cause an error")
	}
}

func TestSettingsParse3(t *testing.T) {
	settings, err := SettingsLoad("../settings.example.yaml")
	if err != nil {
		t.Errorf("Could not parse yaml %v", err)
	}
	settings.Validity = maxmins + 1
	err = settings.validate()
	t.Logf("Error (expected): %s", err)
	if err == nil {
		t.Errorf("Invalid validity did not cause an error")
	}
}

func TestSettingsParse4(t *testing.T) {
	settings, err := SettingsLoad("../settings.example.yaml")
	if err != nil {
		t.Errorf("Could not parse yaml %v", err)
	}
	settings.Extensions = map[string]string{}
	err = settings.validate()
	if err != nil {
		t.Errorf("empty extensions caused a problem")
	}
}

func TestSettingsParse5(t *testing.T) {
	settings, err := SettingsLoad("../settings.example.yaml")
	if err != nil {
		t.Errorf("Could not parse yaml %v", err)
	}
	settings.Extensions["permit-agent-forwarding"] = "nonsense"
	err = settings.validate()
	t.Logf("Error (expected): %s", err)
	if err == nil {
		t.Errorf("should not allow nonsense value in extension")
	}
}

func TestSettingsParse6(t *testing.T) {
	settings, err := SettingsLoad("../settings.example.yaml")
	if err != nil {
		t.Errorf("Could not parse yaml %v", err)
	}
	settings.Extensions["random-extension"] = ""
	err = settings.validate()
	t.Logf("Error (expected): %s", err)
	if err == nil {
		t.Errorf("should not allow random extension")
	}
}

// duplicate ssh keys
func TestSettingsParse7(t *testing.T) {
	_, err := SettingsLoad("testdata/settings_broken1.yaml")
	t.Logf("%+v", err)
	if !ErrorContains(err, "user bill key already exists") {
		t.Errorf("Unexpected error %v", err)
	}
}

// invalid ssh key
func TestSettingsParse8(t *testing.T) {
	_, err := SettingsLoad("testdata/settings_broken2.yaml")
	t.Logf("%+v", err)
	if !ErrorContains(err, "yaml error: user bill has an invalid public key: ssh: no key found") {
		t.Errorf("Unexpected error %v", err)
	}
}

// invalid principals
func TestSettingsParse9(t *testing.T) {
	_, err := SettingsLoad("testdata/settings_broken3.yaml")
	t.Logf("%+v", err)
	if !ErrorContains(err, "user bill provided with no principals") {
		t.Errorf("Unexpected error %v", err)
	}
}

// invalid yaml file (tab)
func TestSettingsParse10(t *testing.T) {
	_, err := SettingsLoad("testdata/settings_broken4.yaml")
	t.Logf("%+v", err)
	if !ErrorContains(err, "yaml: line 4: found a tab character that violates indentation") {
		t.Errorf("Unexpected error %v", err)
	}
}

// no user name
func TestSettingsParse11(t *testing.T) {
	_, err := SettingsLoad("testdata/settings_broken5.yaml")
	t.Logf("%+v", err)
	if !ErrorContains(err, "user provided with empty name") {
		t.Errorf("Unexpected error %v", err)
	}
}

// no users
func TestSettingsParse12(t *testing.T) {
	_, err := SettingsLoad("testdata/settings_broken6.yaml")
	t.Logf("%+v", err)
	if !ErrorContains(err, "no valid users found in yaml file") {
		t.Errorf("Unexpected error %v", err)
	}
}

func TestUserSettings1(t *testing.T) {
	settings, err := SettingsLoad("../settings.example.yaml")
	if err != nil {
		t.Errorf("Could not parse yaml %v", err)
	}
	if len(settings.Users) != 2 {
		t.Errorf("unexpected user length encountered")
	}
	settings.Users[0].Fingerprint = settings.Users[0].Fingerprint[1:]
	err = settings.validate()
	t.Logf("Error (expected): SHA error %s", err)
	if err == nil {
		t.Errorf("fingerprint 'sha256:' check failed")
	}
}

func TestUserSettings2(t *testing.T) {
	settings, err := SettingsLoad("../settings.example.yaml")
	if err != nil {
		t.Errorf("Could not parse yaml %v", err)
	}
	settings.Users[0].Fingerprint = settings.Users[0].Fingerprint[:49]
	err = settings.validate()
	t.Logf("Error (expected): fingerprint length error %s", err)
	if err == nil {
		t.Errorf("fingerprint length check failed")
	}
}

func TestUserSettings3(t *testing.T) {
	settings, err := SettingsLoad("../settings.example.yaml")
	if err != nil {
		t.Errorf("Could not parse yaml %v", err)
	}
	settings.Users[0].Principals = []string{}
	err = settings.validate()
	t.Logf("Error (expected): no principals error %s", err)
	if err == nil {
		t.Errorf("empty principals error passed")
	}
}

func TestUserSettings4(t *testing.T) {
	settings, err := SettingsLoad("../settings.example.yaml")
	if err != nil {
		t.Errorf("Could not parse yaml %v", err)
	}
	settings.Users[0].Principals = []string{}
	err = settings.validate()
	t.Logf("Error (expected): no principals error %s", err)
	if err == nil {
		t.Errorf("empty principals error passed")
	}
}

func TestUserSettings5(t *testing.T) {
	settings, err := SettingsLoad("../settings.example.yaml")
	if err != nil {
		t.Errorf("Could not parse yaml %v", err)
	}
	settings.Users[0].Principals = []string{}
	err = settings.validate()
	t.Logf("Error (expected): no principals error %s", err)
	if err == nil {
		t.Errorf("empty principals error passed")
	}
}

func TestUserSettings6(t *testing.T) {
	settings, err := SettingsLoad("../settings.example.yaml")
	if err != nil {
		t.Errorf("Could not parse yaml %v", err)
	}
	fp := settings.Users[0].Fingerprint
	_, err = settings.UserByFingerprint(fp)
	if err != nil {
		t.Errorf("UserByFingerprint lookup failed")
	}
	fp = settings.Users[0].Fingerprint[1:]
	_, err = settings.UserByFingerprint(fp)
	if err == nil {
		t.Errorf("Invalid UserByFingerprint lookup succeeded")
	}
}

func TestUserAuth1(t *testing.T) {
	settings, err := SettingsLoad("../settings.example.yaml")
	if err != nil {
		t.Errorf("Could not parse yaml %v", err)
	}
	settings.Users[0].PublicKey = nil
	err = settings.validate()
	if err == nil {
		t.Errorf("nil publickey should not be allowed")
	}
}

func TestUserAuth2(t *testing.T) {
	settings, err := SettingsLoad("../settings.example.yaml")
	if err != nil {
		t.Errorf("Could not parse yaml %v", err)
	}
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		panic("Could not generate test privKey")
	}
	pubKey, err := ssh.NewPublicKey(&privKey.PublicKey)
	if err != nil {
		panic("Could not generate test pubkey")
	}
	settings.Users[0].PublicKey = pubKey
	err = settings.validate()
	if err == nil {
		t.Errorf("invalid publickey should not be allowed")
	}
}

func TestSettingsValidate(t *testing.T) {
	_, err := SettingsLoad("../settings.example.yaml")
	if err != nil {
		t.Errorf("validation failed")
	}
}
