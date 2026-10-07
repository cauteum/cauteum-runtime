package agent

import "time"

// Operational defaults owned by this package.
const (
	requestTimeout = 65 * time.Second
	pollTimeout    = 60 * time.Second
	retryInterval  = 2 * time.Second
)
