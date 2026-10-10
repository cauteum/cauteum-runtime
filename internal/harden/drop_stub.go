//go:build !linux

package harden

import "errors"

import "github.com/cauteum-haven/cauteum-core/policy"

var errPrivilegeDropUnavailable = errors.New("privilege drop only available on linux")

func dropPrivileges(_ policy.Document) error {
	return errPrivilegeDropUnavailable
}
