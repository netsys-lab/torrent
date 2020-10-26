// Downloads torrents from the command-line.
package main

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/anacrolix/tagflag"
	"github.com/anacrolix/utp"
	log "github.com/inconshreveable/log15"
	// "github.com/netsec-ethz/scion-apps/pkg/appnet"
)

var flags = struct {
	IsServer  bool
	NumCons   int
	StartPort int
	tagflag.StartPos
}{
	IsServer:  true,
	NumCons:   1,
	StartPort: 42522,
}

const (
	PacketSize int64 = 9000
	NumPackets int64 = 200000
)

func LogFatal(msg string, a ...interface{}) {
	log.Crit(msg, a...)
	os.Exit(1)
}

func Check(e error) {
	if e != nil {
		LogFatal("Fatal error. Exiting.", "err", e)
	}
}

func main() {
	if err := mainErr(); err != nil {
		log.Info("error in main: %v", err)
		os.Exit(1)
	}
}

func mainErr() error {
	tagflag.Parse(&flags)
	startPort := flags.StartPort
	i := 0
	var wg sync.WaitGroup
	for i < flags.NumCons {
		go func(wg *sync.WaitGroup, startPort int, i int) {
			defer wg.Done()
			if flags.IsServer {
				runServer(startPort + i)
			} else {
				runClient(startPort + i)
			}
		}(&wg, startPort, i)
		i++
	}
	wg.Wait()
	time.Sleep(time.Minute * 5)
	return nil
}

func runClient(startPort int) {
	s, err := utp.NewSocket("udp", fmt.Sprintf("10.0.0.1:%d", startPort))
	Check(err)
	fmt.Println("Created socket")
	conn, err := s.Dial(fmt.Sprintf("10.0.0.2:%d", startPort))
	Check(err)
	fmt.Println("Created conn")
	// clientCCAddr := CCConn.LocalAddr().(*net.UDPAddr)
	sb := make([]byte, PacketSize)
	// Data channel connection
	// DCConn, err := appnet.DefNetwork().Dial(
	//	context.TODO(), "udp", clientCCAddr, serverAddr, addr.SvcNone)
	// Check(err)
	var i int64 = 0
	start := time.Now()
	for i < NumPackets {
		// Compute how long to wait

		// PrgFill(bwp.PrgKey, int(i*bwp.PacketSize), sb)
		// Place packet number at the beginning of the packet, overwriting some PRG data
		// fmt.Printf("Write %d bytes to conn", len(sb))
		_, err := conn.Write(sb)
		// fmt.Printf("Wrote %d bytes to conn", n)
		Check(err)
		i++
	}
	elapsed := time.Since(start)
	fmt.Printf("Binomial took %s\n", elapsed)
}

func runServer(startPort int) error {

	s, err := utp.NewSocket("udp", fmt.Sprintf("10.0.0.2:%d", startPort))
	Check(err)
	conn, err := s.Accept()
	Check(err)
	// conn, err := appnet.ListenPort(port)

	var numPacketsReceived int64
	numPacketsReceived = 0
	recBuf := make([]byte, PacketSize+1000)
	go func() {
		time.Sleep(5 * time.Second)
		fmt.Printf("Received %d packets\n", numPacketsReceived)
	}()
	for numPacketsReceived < NumPackets {
		n, err := conn.Read(recBuf)

		// Ignore errors, todo: detect type of error and quit if it was because of a SetReadDeadline
		if err != nil {
			fmt.Println(err)
			continue
		}
		if int64(n) != PacketSize {
			// The packet has incorrect size, do not count as a correct packet
			// fmt.Println("Incorrect size.", n, "bytes instead of", PacketSize)
			continue
		}
		// fmt.Printf("Read packet of size %d\n", n)
		numPacketsReceived++
		// fmt.Printf("Received %d packets\n", numPacketsReceived)
	}

	fmt.Printf("Received all packets")
	return nil
}
