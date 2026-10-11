//go:build !darwin

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 VoS contributors.

package core

import (
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/protocol/tun"
)

func registerTUNInbound(registry *inbound.Registry) { tun.RegisterInbound(registry) }
