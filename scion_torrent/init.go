package scion_torrent

import (
	"crypto/tls"
	"os"
	"sync"

	"github.com/scionproto/scion/go/lib/addr"
	//	"github.com/scionproto/scion/go/lib/sciond"
	//	"github.com/scionproto/scion/go/lib/snet"
	// "github.com/scionproto/scion/go/lib/snet/squic"
	//	"github.com/scionproto/scion/go/lib/sock/reliable"
)

var quicInit sync.Once
var scionInit sync.Once
var (
	// Don't verify the server's cert, as we are not using the TLS PKI.
	TLSCfg = &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}
)

// GetDefaultDispatcher returns the default SCION dispatcher service
//func GetDefaultDispatcher() reliable.DispatcherService {
//	return reliable.NewDispatcherService("")
//}

// InitSQUICCerts reads certificate files from the os environment and Initializes the scion QUIC layer.
func InitSQUICCerts() error {
	var initErr error
	quicInit.Do(func() {
		// initErr = squic.Init(os.Getenv("SCION_CERT_KEY_FILE"), os.Getenv("SCION_CERT_FILE"))
		cert, err := tls.LoadX509KeyPair(os.Getenv("SCION_CERT_FILE"), os.Getenv("SCION_CERT_KEY_FILE"))
		initErr = err
		TLSCfg.Certificates = []tls.Certificate{cert}
	})
	return initErr
}

func InitScion(myAddr addr.IA) error {
	var initErr error
	scionInit.Do(func() {
		// initErr = snet.Init(myAddr, sciondPath, dispatcher)
	})
	return initErr
}
