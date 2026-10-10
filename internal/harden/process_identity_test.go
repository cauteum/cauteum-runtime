package harden

import (
	"testing"

	"github.com/cautem/cauteum-core/policy"
)

func TestProcessIdentityFailureIsNeverBestEffort(t *testing.T) {
	_, err := Apply(t.Context(), Options{
		Doc:  policy.Document{Process: &policy.Process{RunAsUser: "cauteum-user-that-does-not-exist"}},
		Mode: ModeBestEffort,
	})
	if err == nil {
		t.Fatal("invalid process identity was ignored in best-effort mode")
	}
}
