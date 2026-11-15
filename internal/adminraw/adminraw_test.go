package adminraw

import (
	"context"
	"testing"
)

// Without pkg/adminclient linked in, there is nothing to call.
func TestDoNeedsTheClientPackage(t *testing.T) {
	if err := Do(context.Background(), nil, "GET", "/v1/admin/x", nil, nil, nil); err == nil {
		t.Error("a call with no registered client succeeded")
	}
}
