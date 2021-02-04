// For local benchmarks only
package main

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

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
	var wg sync.WaitGroup

	if flags.IsServer {
		if flags.Mode == "TCP" {
			for i, torrent := range flags.Torrent {
				wg.Add(1)
				go func(wg *sync.WaitGroup, tr string, i int) {
					defer wg.Done()
					cmd := exec.Command("./benchtorrent", tr, "-tcpOnly", "-seed", fmt.Sprintf("-tcpPort=%d", startPort+i))
					outfile, err := os.Create(fmt.Sprintf("./out-%d.txt", i))
					if err != nil {
						panic(err)
					}
					defer outfile.Close()

					cmd.Stdout = outfile
					log.Print(cmd.Args)
					err = cmd.Start()
					cmd.Wait()
					log.Printf("Command finished with error: %v", err)
				}(&wg, torrent, i)
			}
		} else if flags.Mode == "UDP" {
			for i, torrent := range flags.Torrent {
				wg.Add(1)
				go func(wg *sync.WaitGroup, tr string, i int) {
					defer wg.Done()
					cmd := exec.Command("./benchtorrent", tr, "-udpOnly", "-seed", fmt.Sprintf("-tcpPort=%d", startPort+i))
					outfile, err := os.Create(fmt.Sprintf("./out-%d.txt", i))
					if err != nil {
						panic(err)
					}
					defer outfile.Close()

					cmd.Stdout = outfile
					log.Print(cmd.Args)
					err = cmd.Start()
					cmd.Wait()
					log.Printf("Command finished with error: %v", err)
				}(&wg, torrent, i)
			}
		} else if flags.Mode == "SCION" {
			for i, torrent := range flags.Torrent {
				wg.Add(1)
				go func(wg *sync.WaitGroup, tr string, i int) {
					defer wg.Done()
					//   ./benchtorrent 'magnet:?xt=urn:btih:9fc20b9e98ea98b4a35e6223041a5ef94ea27809' -seed -scion -42425'
					cmd := exec.Command("./benchtorrent", tr, "-scion", "-scionOnly", "-seed", fmt.Sprintf("-localScionAddr=19-ffaa:1:c3f,[10.0.0.2]:%d", startPort+i), fmt.Sprintf("-tcpPort=%d", startPort+i))
					cmd.Env = os.Environ()
					cmd.Env = append(cmd.Env, "SCION_CERT_KEY_FILE=/home/martin/mgartner/key.pem")
					cmd.Env = append(cmd.Env, "SCION_CERT_FILE=/home/martin/mgartner/cert.pem")
					// fmt.Print(cmd.Env)
					outfile, err := os.Create(fmt.Sprintf("./out-%d.txt", i))
					if err != nil {
						panic(err)
					}
					defer outfile.Close()

					cmd.Stdout = outfile
					cmd.Stderr = outfile
					log.Print(cmd.Args)
					err = cmd.Start()
					cmd.Wait()
					log.Printf("Command finished with error: %v", err)
				}(&wg, torrent, i)
			}
		}
	} else {
		if flags.Mode == "TCP" {
			for i, torrent := range flags.Torrent {
				go func(tr string, i int) {
					cmd := exec.Command("./benchtorrent", tr, "-tcpOnly", fmt.Sprintf("-tcpAddrList=10.0.0.2:%d", startPort+i), "-pClient", "-stats", "-maxRequestsPerPeer=20000", fmt.Sprintf("-tcpPort=%d", startPort+i), "-maxConnectionsPerPeer=3")

					outfile, err := os.Create(fmt.Sprintf("./out-%d.txt", i))
					if err != nil {
						panic(err)
					}
					defer outfile.Close()

					cmd.Stdout = outfile
					log.Print(cmd.Args)
					err = cmd.Start()
					cmd.Wait()
					log.Printf("Command finished with error: %v", err)
				}(torrent, i)
			}
		} else if flags.Mode == "UDP" {
			for i, torrent := range flags.Torrent {
				go func(tr string, i int) {
					cmd := exec.Command("./benchtorrent", tr, "-udpOnly", fmt.Sprintf("-udpAddrList=10.0.0.2:%d", startPort+i), "-pClient", "-stats", "-maxRequestsPerPeer=20000", fmt.Sprintf("-tcpPort=%d", startPort+i), "-maxConnectionsPerPeer=3")
					outfile, err := os.Create(fmt.Sprintf("./out-%d.txt", i))
					if err != nil {
						panic(err)
					}
					defer outfile.Close()

					cmd.Stdout = outfile
					log.Print(cmd.Args)
					err = cmd.Start()
					cmd.Wait()
					log.Printf("Command finished with error: %v", err)
				}(torrent, i)
			}
		} else if flags.Mode == "SCION" {
			for i, torrent := range flags.Torrent {
				go func(tr string, i int) {
					// ./benchtorrent 'magnet:?xt=urn:btih:9fc20b9e98ea98b4a35e6223041a5ef94ea27809' -scion -scionOnly -42425' -42425'  -maxRequestsPerPeer=2000
					cmd := exec.Command("./benchtorrent", tr, "-scion", "-scionOnly", "-timeSlotInterval=1000", fmt.Sprintf("-peerScionAddrList=19-ffaa:1:c3f,[10.0.0.2]:%d", startPort+i), fmt.Sprintf("-localScionAddr=19-ffaa:1:cf0,[127.0.0.1]:%d", startPort+i), "-stats", fmt.Sprintf("-tcpPort=%d", startPort+i), "-pClient", "-maxConnectionsPerPeer=2", "numMaxCons=3", "-allowDuplicatePaths", "-reuseFirstPath")
					cmd.Env = os.Environ()
					cmd.Env = append(cmd.Env, "SCION_CERT_KEY_FILE=key.pem")
					cmd.Env = append(cmd.Env, "SCION_CERT_FILE=cert.pem")

					perfPids, ok := os.LookupEnv("PERF_PIDS")
					if ok {
						cmd.Env = append(cmd.Env, fmt.Sprintf("PERF_PIDS=%s", perfPids))
					}

					outfile, err := os.Create(fmt.Sprintf("./out-%d.txt", i))
					if err != nil {
						panic(err)
					}
					defer outfile.Close()

					cmd.Stdout = outfile
					log.Print(cmd.Args)
					err = cmd.Start()
					cmd.Wait()
					log.Printf("Command %d finished with error: %v", i, err)
				}(torrent, i)
			}
		}
	}
	wg.Wait()
	time.Sleep(time.Minute * 120)
	return nil
}
