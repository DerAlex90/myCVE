//go:build !windows

// Copyright (c) 2026 Alexander Speka (DerAlex90)
// SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

package service

import (
	"context"
	"errors"
)

func Run(ctx context.Context, run func(context.Context) error) error { return run(ctx) }
func Manage(_ string, _ string, _ string) error {
	return errors.New("on Linux, use deploy/linux/install.sh and systemctl; Windows service management is Windows-only")
}
