//go:build !linux

package harden

import (
	"errors"

	"github.com/cautem/cauteum-core/policy"
)

var errLandlockUnavailable = errors.New("landlock only available on linux")

func landlockABI() (int, error) {
	return 0, errLandlockUnavailable
}

func applyLandlock(_ policy.Document) error {
	return errLandlockUnavailable
}
