package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/DerAlex90/myCVE/agent/internal/client"
	"github.com/DerAlex90/myCVE/agent/internal/collector"
	"github.com/DerAlex90/myCVE/agent/internal/protocol"
)

type Uploader interface {
	Upload(context.Context, []byte) (protocol.Acknowledgement, error)
}

type Runner struct {
	Config   client.Config
	Uploader Uploader
	Collect  func(context.Context, string, []string) (protocol.Inventory, error)
}

func (runner *Runner) flush(ctx context.Context) error {
	path := filepath.Join(runner.Config.StateDir, "pending.json")
	file, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if file.Size() > protocol.MaxBytes {
		return errors.New("pending inventory exceeds 10 MB")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var stored protocol.Inventory
	if err := json.Unmarshal(payload, &stored); err != nil {
		return errors.New("pending inventory is invalid; inspect local state")
	}
	ack, err := runner.Uploader.Upload(ctx, payload)
	if err != nil {
		return err
	}
	if ack.SnapshotID != stored.SnapshotID || (!ack.Accepted && !ack.Stale) {
		return errors.New("pending report was not acknowledged; retained for retry")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	log.Printf("inventory acknowledged: report=%s partial=%t duplicate=%t stale=%t", ack.SnapshotID, ack.Partial, ack.Duplicate, ack.Stale)
	return nil
}

func (runner *Runner) Cycle(ctx context.Context) error {
	// Retry the exact persisted report first. If it fails, retain it for the next attempt.
	if err := runner.flush(ctx); err != nil {
		return err
	}
	id, err := DeviceID(runner.Config.StateDir)
	if err != nil {
		return err
	}
	collect := runner.Collect
	if collect == nil {
		collect = collector.Collect
	}
	report, err := collect(ctx, id, runner.Config.SBOMPaths)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(report)
	if err != nil {
		return err
	}
	if len(payload) > protocol.MaxBytes {
		return errors.New("collected inventory exceeds 10 MB; reduce configured SBOMs")
	}
	if err := AtomicWrite(filepath.Join(runner.Config.StateDir, "pending.json"), payload); err != nil {
		return err
	}
	return runner.flush(ctx)
}

func Run(ctx context.Context, config client.Config, once bool) error {
	unlock, err := Lock(config.StateDir)
	if err != nil {
		return err
	}
	defer unlock()
	httpClient, err := client.New(config)
	if err != nil {
		return err
	}
	defer httpClient.Close()
	runner := Runner{Config: config, Uploader: httpClient}
	backoff := time.Minute
	for {
		err := runner.Cycle(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if once {
			return err
		}
		delay := time.Duration(config.IntervalSeconds) * time.Second
		if err != nil {
			log.Printf("inventory transfer failed; pending data retained: %v", err)
			delay = backoff
			if backoff < 15*time.Minute {
				backoff *= 2
			}
		} else {
			backoff = time.Minute
		}
		// Device-specific jitter spreads fleet load without transmitting additional identifiers.
		id, _ := DeviceID(config.StateDir)
		if len(id) > 0 {
			delay += time.Duration(int(id[0])%30) * time.Second
		}
		log.Printf("next attempt in %s", delay.Round(time.Second))
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func Collect(config client.Config) ([]byte, error) {
	unlock, err := Lock(config.StateDir)
	if err != nil {
		return nil, err
	}
	defer unlock()
	id, err := DeviceID(config.StateDir)
	if err != nil {
		return nil, err
	}
	report, err := collector.Collect(context.Background(), id, config.SBOMPaths)
	if err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("cannot encode inventory: %w", err)
	}
	return data, nil
}
