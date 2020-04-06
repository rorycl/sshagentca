package util

import (
	"github.com/rorycl/sshagentca/util"
	"testing"
)

func TestSettingsParse(t *testing.T) {

	settings, err := util.SettingsLoad("../settings.example.yaml", false)
	if err != nil {
		t.Errorf("Could not parse yaml file %v", err)
	}

	t.Logf("Settings : %+v", settings)
}

func TestSettingsParse2(t *testing.T) {

	settings, err := util.SettingsLoad("../settings.example.yaml", true)
	if err != nil {
		t.Errorf("Could not parse yaml file %v", err)
	}

	settings.Validity = -1
	err = settings.Validate()
	t.Logf("Error (expected): %s", err)
	if err == nil {
		t.Errorf("Invalid validity did not cause an error")
	}
}

func TestSettingsParse3(t *testing.T) {

	settings, err := util.SettingsLoad("../settings.example.yaml", true)
	if err != nil {
		t.Errorf("Could not parse yaml file %v", err)
	}

	settings.Validity = maxmins + 1
	err = settings.Validate()
	t.Logf("Error (expected): %s", err)
	if err == nil {
		t.Errorf("Invalid validity did not cause an error")
	}
}

func TestSettingsParse4(t *testing.T) {

	settings, err := util.SettingsLoad("../settings.example.yaml", true)
	if err != nil {
		t.Errorf("Could not parse yaml file %v", err)
	}

	settings.Extensions = map[string]string{}
	err = settings.Validate()
	if err != nil {
		t.Errorf("empty extensions caused a problem")
	}
}

func TestSettingsParse5(t *testing.T) {

	settings, err := util.SettingsLoad("../settings.example.yaml", true)
	if err != nil {
		t.Errorf("Could not parse yaml file %v", err)
	}

	settings.Extensions["permit-agent-forwarding"] = "nonsense"
	err = settings.Validate()
	t.Logf("Error (expected): %s", err)
	if err == nil {
		t.Errorf("should not allow nonsense value in extension")
	}
}

func TestSettingsParse6(t *testing.T) {

	settings, err := util.SettingsLoad("../settings.example.yaml", true)
	if err != nil {
		t.Errorf("Could not parse yaml file %v", err)
	}

	settings.Extensions["random-extension"] = ""
	err = settings.Validate()
	t.Logf("Error (expected): %s", err)
	if err == nil {
		t.Errorf("should not allow random extension")
	}
}
