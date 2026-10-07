package harden

import (
	"testing"

	"github.com/whaleshell/whaleshell-core/policy"
)

func TestProcessIdentityFailureIsNeverBestEffort(t *testing.T) {
	_, err := Apply(t.Context(), Options{
		Doc:  policy.Document{Process: &policy.Process{RunAsUser: "whaleshell-user-that-does-not-exist"}},
		Mode: ModeBestEffort,
	})
	if err == nil {
		t.Fatal("invalid process identity was ignored in best-effort mode")
	}
}
