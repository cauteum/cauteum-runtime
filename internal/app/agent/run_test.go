// SPDX-FileCopyrightText: Copyright (c) 2026 cautem
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"strings"
	"testing"
)

func TestCappedBufferTruncates(t *testing.T) {
	var buf cappedBuffer
	buf.max = 8
	n, err := buf.Write([]byte("abcdefghij"))
	if err != nil || n != 10 {
		t.Fatalf("Write n=%d err=%v", n, err)
	}
	s := buf.String()
	if !strings.HasPrefix(s, "abcdefgh") {
		t.Fatalf("prefix=%q", s)
	}
	if !strings.Contains(s, "[truncated]") {
		t.Fatalf("missing truncated marker: %q", s)
	}
	// Further writes discarded.
	_, _ = buf.Write([]byte("MORE"))
	if strings.Contains(buf.String(), "MORE") {
		t.Fatalf("wrote past cap: %q", buf.String())
	}
}
