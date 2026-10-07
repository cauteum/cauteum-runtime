package wsinit

import (
	"reflect"
	"testing"
)

func TestWorkloadEnvironmentStripsSupervisorOnlyOpenShellVariables(t *testing.T) {
	in := []string{
		"PATH=/usr/bin",
		"OPENSHELL_SANDBOX_UID=1000",
		"OPENSHELL_SANDBOX_GID=1000",
		"OPENSHELL_SANDBOX_TOKEN=secret",
		"OPENSHELL_TLS_KEY=/run/secrets/key",
		"OPENSHELL_NETWORK_RUNTIME_CAPABILITIES=policy-dns-transparent-tcp",
		"OPENSHELL_USER_ENVIRONMENT={}",
		"OPENAI_API_KEY=workload-secret",
	}
	want := []string{
		"PATH=/usr/bin",
		"OPENSHELL_USER_ENVIRONMENT={}",
		"OPENAI_API_KEY=workload-secret",
	}
	if got := workloadEnvironment(in); !reflect.DeepEqual(got, want) {
		t.Fatalf("workloadEnvironment() = %v, want %v", got, want)
	}
}
