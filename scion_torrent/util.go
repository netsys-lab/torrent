package scion_torrent

import (
	"github.com/scionproto/scion/go/lib/sock/reliable"
)

// GetDefaultDispatcher returns the default SCION dispatcher service
func GetDefaultDispatcher() reliable.DispatcherService {
	return reliable.NewDispatcherService("")
}
