//go:build !windows && !linux

package collector

import (
	"context"
	"errors"

	"github.com/DerAlex90/myCVE/agent/internal/protocol"
)

func platformCollect(_ context.Context, _ *protocol.Host) []protocol.Collector {
	return []protocol.Collector{failed("system", errors.New("native inventory is supported on Linux and Windows; explicit SBOM files remain available"))}
}
