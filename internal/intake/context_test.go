package intake

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestReadContextStopsBeforeAccessAndBetweenReads(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	reader := contextReader{ctx, strings.NewReader("first second")}
	buffer := make([]byte, 5)
	if count, err := reader.Read(buffer); err != nil || count != 5 {
		t.Fatalf("first read %d %v", count, err)
	}
	cancel()
	if count, err := reader.Read(buffer); count != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled read %d %v", count, err)
	}
	if _, err := ReadContext(ctx, []string{"missing input"}, options); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled intake: %v", err)
	}
}
