package util

import (
	"testing"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"golang.org/x/crypto/ssh"
)

func TestSettingsParse(t *testing.T) {
	settings, err := SettingsLoad("../settings.example.yaml", "testdata/test_authorized_keys")
	if err != nil {
		t.Errorf("Could not parse yaml or authorized keys file %v", err)
	}
	t.Logf("Settings : %+v", settings)
}

func TestSettingsParse2(t *testing.T) {
	settings, err := SettingsLoad("../settings.example.yaml", "testdata/test_authorized_keys")
	if err != nil {
		t.Errorf("Could not parse yaml or authorized keys file %v", err)
	}
	settings.Validity = 0
	err = settings.validate()
	t.Logf("Error (expected): %s", err)
	if err == nil {
		t.Errorf("Invalid validity did not cause an error")
	}
}

func TestSettingsParse3(t *testing.T) {
	settings, err := SettingsLoad("../settings.example.yaml", "testdata/test_authorized_keys")
	if err != nil {
		t.Errorf("Could not parse yaml or authorized keys file %v", err)
	}
	settings.Validity = maxmins + 1
	err = settings.validate()
	t.Logf("Error (expected): %s", err)
	if err == nil {
		t.Errorf("Invalid validity did not cause an error")
	}
}

func TestSettingsParse4(t *testing.T) {
	settings, err := SettingsLoad("../settings.example.yaml", "testdata/test_authorized_keys")
	if err != nil {
		t.Errorf("Could not parse yaml or authorized keys file %v", err)
	}
	settings.Extensions = map[string]string{}
	err = settings.validate()
	if err != nil {
		t.Errorf("empty extensions caused a problem")
	}
}

func TestSettingsParse5(t *testing.T) {
	settings, err := SettingsLoad("../settings.example.yaml", "testdata/test_authorized_keys")
	if err != nil {
		t.Errorf("Could not parse yaml or authorized keys file %v", err)
	}
	settings.Extensions["permit-agent-forwarding"] = "nonsense"
	err = settings.validate()
	t.Logf("Error (expected): %s", err)
	if err == nil {
		t.Errorf("should not allow nonsense value in extension")
	}
}

func TestSettingsParse6(t *testing.T) {
	settings, err := SettingsLoad("../settings.example.yaml", "testdata/test_authorized_keys")
	if err != nil {
		t.Errorf("Could not parse yaml or authorized keys file %v", err)
	}
	settings.Extensions["random-extension"] = ""
	err = settings.validate()
	t.Logf("Error (expected): %s", err)
	if err == nil {
		t.Errorf("should not allow random extension")
	}
}

func TestUserSettings1(t *testing.T) {
	settings, err := SettingsLoad("../settings.example.yaml", "testdata/test_authorized_keys")
	if err != nil {
		t.Errorf("Could not parse yaml or authorized keys file %v", err)
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
	settings, err := SettingsLoad("../settings.example.yaml", "testdata/test_authorized_keys")
	if err != nil {
		t.Errorf("Could not parse yaml or authorized keys file %v", err)
	}
	settings.Users[0].Fingerprint = settings.Users[0].Fingerprint[:49]
	err = settings.validate()
	t.Logf("Error (expected): fingerprint length error %s", err)
	if err == nil {
		t.Errorf("fingerprint length check failed")
	}
}

func TestUserSettings3(t *testing.T) {
	settings, err := SettingsLoad("../settings.example.yaml", "testdata/test_authorized_keys")
	if err != nil {
		t.Errorf("Could not parse yaml or authorized keys file %v", err)
	}
	settings.Users[0].Principals = []string{}
	err = settings.validate()
	t.Logf("Error (expected): no principals error %s", err)
	if err == nil {
		t.Errorf("empty principals error passed")
	}
}

func TestUserSettings4(t *testing.T) {
	settings, err := SettingsLoad("../settings.example.yaml", "testdata/test_authorized_keys")
	if err != nil {
		t.Errorf("Could not parse yaml or authorized keys file %v", err)
	}
	settings.Users[0].Principals = []string{}
	err = settings.validate()
	t.Logf("Error (expected): no principals error %s", err)
	if err == nil {
		t.Errorf("empty principals error passed")
	}
}

func TestUserSettings5(t *testing.T) {
	settings, err := SettingsLoad("../settings.example.yaml", "testdata/test_authorized_keys")
	if err != nil {
		t.Errorf("Could not parse yaml or authorized keys file %v", err)
	}
	settings.Users[0].Principals = []string{}
	err = settings.validate()
	t.Logf("Error (expected): no principals error %s", err)
	if err == nil {
		t.Errorf("empty principals error passed")
	}
}

func TestUserSettings6(t *testing.T) {
	settings, err := SettingsLoad("../settings.example.yaml", "testdata/test_authorized_keys")
	if err != nil {
		t.Errorf("Could not parse yaml or authorized keys file %v", err)
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
	settings, err := SettingsLoad("../settings.example.yaml", "testdata/test_authorized_keys")
	if err != nil {
		t.Errorf("Could not parse yaml or authorized keys file %v", err)
	}
	settings.Users[0].PublicKey = nil
	err = settings.validate()
	if err == nil {
		t.Errorf("nil publickey should not be allowed")
	}
}

func TestUserAuth2(t *testing.T) {
	settings, err := SettingsLoad("../settings.example.yaml", "testdata/test_authorized_keys")
	if err != nil {
		t.Errorf("Could not parse yaml or authorized keys file %v", err)
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
	_, err := SettingsLoad("../settings.example.yaml", "testdata/test_authorized_keys")
	if err != nil {
		t.Errorf("validation failed")
	}
}
