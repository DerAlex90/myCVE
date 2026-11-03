//go:build windows

// Copyright (c) 2026 Alexander Speka (DerAlex90)
// SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const Name = "myCVEAgent"

type handler struct{ run func(context.Context) error }
type eventWriter struct{ log *eventlog.Log }

func (writer eventWriter) Write(data []byte) (int, error) {
	err := writer.log.Info(1, string(data))
	return len(data), err
}

func (h *handler) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil {
				log.Printf("agent stopped: %v", err)
				return true, 1
			}
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				changes <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending, WaitHint: 30000}
				cancel()
				select {
				case <-done:
					return false, 0
				case <-time.After(25 * time.Second):
					return true, 2
				}
			}
		}
	}
}

func Run(ctx context.Context, run func(context.Context) error) error {
	inside, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !inside {
		return run(ctx)
	}
	if writer, err := eventlog.Open(Name); err == nil {
		defer writer.Close()
		log.SetOutput(eventWriter{log: writer})
	}
	return svc.Run(Name, &handler{run: run})
}

func Manage(action, configPath, stateDir string) error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("Windows service manager unavailable (administrator required): %w", err)
	}
	defer manager.Disconnect()
	if action == "install" {
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		configPath, err = filepath.Abs(configPath)
		if err != nil {
			return err
		}
		args := []string{"run", "--config", configPath}
		if stateDir != "" {
			args = append(args, "--state-dir", stateDir)
		}
		existing, err := manager.OpenService(Name)
		if err == nil {
			existing.Close()
			return errors.New("service already exists; use the installer to stop and replace it before upgrading")
		}
		created, err := manager.CreateService(Name, executable, mgr.Config{DisplayName: "myCVE Inventory Agent", Description: "Collects installed software and submits device-scoped inventory to myCVE.", StartType: mgr.StartAutomatic}, args...)
		if err != nil {
			return err
		}
		defer created.Close()
		if err := created.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 15 * time.Second}, {Type: mgr.ServiceRestart, Delay: 60 * time.Second}}, 86400); err != nil {
			created.Delete()
			return err
		}
		if err := eventlog.InstallAsEventCreate(Name, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
			log.Printf("Event Log registration unavailable")
		}
		return nil
	}
	installed, err := manager.OpenService(Name)
	if err != nil {
		return err
	}
	defer installed.Close()
	switch action {
	case "start":
		return installed.Start()
	case "stop":
		status, err := installed.Query()
		if err != nil {
			return err
		}
		if status.State == svc.Stopped {
			return nil
		}
		if _, err := installed.Control(svc.Stop); err != nil {
			return err
		}
		for i := 0; i < 60; i++ {
			status, err = installed.Query()
			if err != nil {
				return err
			}
			if status.State == svc.Stopped {
				return nil
			}
			time.Sleep(500 * time.Millisecond)
		}
		return errors.New("service did not stop in 30 seconds")
	case "uninstall":
		status, err := installed.Query()
		if err != nil {
			return err
		}
		if status.State != svc.Stopped {
			return errors.New("stop the service before uninstalling")
		}
		if err := installed.Delete(); err != nil {
			return err
		}
		eventlog.Remove(Name)
		return nil
	default:
		return errors.New("service action must be install, start, stop or uninstall")
	}
}
