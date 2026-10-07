package harden

import "github.com/whaleshell/whaleshell-core/policy"

type filesystemPathOwner struct{}

func newFilesystemPathOwner(policy.Document) *filesystemPathOwner {
	return &filesystemPathOwner{}
}

func (*filesystemPathOwner) resolve() error     { return nil }
func (*filesystemPathOwner) apply(string) error { return nil }
