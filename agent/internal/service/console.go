//go:build !windows

package service

import (
	"context"
	"errors"
)

func Run(ctx context.Context, run func(context.Context) error) error { return run(ctx) }
func Manage(_ string, _ string, _ string) error {
	return errors.New("on Linux, use deploy/linux/install.sh and systemctl; Windows service management is Windows-only")
}
