// Downloads torrents from the command-line.
package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/anacrolix/log"

	"github.com/anacrolix/tagflag"
	// "github.com/netsec-ethz/scion-apps/pkg/appnet"
)

var flags = struct {
	Mode     string
	IsServer bool

	tagflag.StartPos
	Torrent []string `arity:"+" help:"torrent file path or magnet uri"`
}{
	Mode:     "TCP",
	IsServer: true,
}

func main() {
	if err := mainErr(); err != nil {
		log.Printf("error in main: %v", err)
		os.Exit(1)
	}
}

func mainErr() error {
	tagflag.Parse(&flags)
	startPort := 42422
	if flags.IsServer {
		if flags.Mode == "TCP" {
			for i, torrent := range flags.Torrent {
				go func(tr string, i int) {
					cmd := exec.Command("./benchtorrent", tr, "-tcpOnly", "-seed", fmt.Sprintf("-tcpPort=%d", startPort+i))
					err := cmd.Run()
					log.Printf("Command finished with error: %v", err)
				}(torrent, i)
			}
		}
	} else {
		if flags.Mode == "TCP" {
			for i, torrent := range flags.Torrent {
				go func(tr string, i int) {
					cmd := exec.Command("./benchtorrent", tr, "-tcpOnly", fmt.Sprintf("-tcpAddrList=10.0.0.2:%d", startPort+i), "-pClient", "-stats", "-maxRequestsPerPeer=20000", fmt.Sprintf("-tcpPort=%d", startPort+i), "-maxConnectionsPerPeer=1")
					err := cmd.Run()
					log.Printf("Command finished with error: %v", err)
				}(torrent, i)
			}
		}
	}

	return nil
}
