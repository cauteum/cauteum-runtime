package supervisor

import (
	"slices"
	"testing"
)

func TestParseArgsRequiresSeparatorAndPreservesArgv(t *testing.T) {
	if _, err := ParseArgs([]string{"sh", "-c", "echo unsafe"}); err == nil {
		t.Fatal("command without explicit separator was accepted")
	}
	got, err := ParseArgs([]string{"--", "sh", "-c", "printf '%s'", "a b"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"sh", "-c", "printf '%s'", "a b"}
	if !slices.Equal(got, want) {
		t.Fatalf("argv=%q, want %q", got, want)
	}
}

func TestRunReturnsWorkloadExitCode(t *testing.T) {
	code, err := Run(workloadArgs(exitCommand(17)...))
	if err != nil || code != 17 {
		t.Fatalf("Run()=(%d,%v), want (17,nil)", code, err)
	}
}

func TestRunRejectsEmptyCommand(t *testing.T) {
	if code, err := Run(nil); err == nil || code != 2 {
		t.Fatalf("Run(nil)=(%d,%v), want usage error", code, err)
	}
}
