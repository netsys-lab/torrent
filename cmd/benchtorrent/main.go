// Downloads torrents from the command-line.
package main

import (
	"context"
	"expvar"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/scionproto/scion/go/lib/snet"

	"golang.org/x/xerrors"

	"github.com/anacrolix/log"

	"github.com/anacrolix/envpprof"
	"github.com/anacrolix/tagflag"
	"github.com/anacrolix/torrent"
	"github.com/anacrolix/torrent/iplist"
	"github.com/anacrolix/torrent/metainfo"
	"github.com/anacrolix/torrent/scion_torrent"
	"github.com/anacrolix/torrent/storage"
	humanize "github.com/dustin/go-humanize"
	"github.com/gosuri/uiprogress"

	// "github.com/netsec-ethz/scion-apps/pkg/appnet"
	"golang.org/x/time/rate"
)

func Map(vs []string, f func(string) string) []string {
	vsm := make([]string, len(vs))
	for i, v := range vs {
		vsm[i] = f(v)
	}
	return vsm
}

// mangleSCIONAddr mangles a SCION address string (if it is one) so it can be
// safely used in the host part of a URL.
func mangleSCIONAddr(address string) string {

	raddr, err := snet.ParseUDPAddr(address)
	if err != nil {
		panic(fmt.Sprintf("mangleSCIONAddr assumes that address is of the form host:port %s", err))
	}

	// Turn this into [IA,IP]:port format. This is a valid host in a URI, as per
	// the "IP-literal" case in RFC 3986, §3.2.2.
	// Unfortunately, this is not currently compatible with snet.ParseUDPAddr,
	// so this will have to be _unmangled_ before use.
	mangledAddr := fmt.Sprintf("[%s,%s]", raddr.IA, raddr.Host.IP)
	if raddr.Host.Port != 0 {
		mangledAddr += fmt.Sprintf(":%d", raddr.Host.Port)
	}
	return mangledAddr
}

func unmangleSCIONAddr(address string) string {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		panic(fmt.Sprintf("unmangleSCIONAddr assumes that address is of the form host:port %s", err))
	}
	// brackets are removed from [I-A,IP] part by SplitHostPort, so this can be
	// parsed with ParseUDPAddr:
	udpAddr, err := snet.ParseUDPAddr(host)
	if err != nil {
		return address
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return address
	}
	udpAddr.Host.Port = int(p)
	return udpAddr.String()
}

var progress = uiprogress.New()
var ctrlcChan = make(chan struct{})

func torrentBar(t *torrent.Torrent) {
	bar := progress.AddBar(1)
	bar.AppendCompleted()
	bar.AppendFunc(func(*uiprogress.Bar) (ret string) {
		select {
		case <-t.GotInfo():
		default:
			return "getting info"
		}
		if t.Seeding() {
			return "seeding"
		} else if t.BytesCompleted() == t.Info().TotalLength() {
			return "completed"
		} else {
			return fmt.Sprintf("downloading (%s/%s)", humanize.Bytes(uint64(t.BytesCompleted())), humanize.Bytes(uint64(t.Info().TotalLength())))
		}
	})
	bar.PrependFunc(func(*uiprogress.Bar) string {
		return t.Name()
	})
	go func() {
		<-t.GotInfo()
		tl := int(t.Info().TotalLength())
		if tl == 0 {
			bar.Set(1)
			return
		}
		bar.Total = tl
		for {
			bc := t.BytesCompleted()
			bar.Set(int(bc))
			time.Sleep(time.Second)
		}
	}()
}

func addTorrents(client *torrent.Client) error {
	for _, arg := range flags.Torrent {
		t, err := func() (*torrent.Torrent, error) {
			if strings.HasPrefix(arg, "magnet:") {
				t, err := client.AddMagnet(arg)
				if err != nil {
					return nil, xerrors.Errorf("error adding magnet: %w", err)
				}
				return t, nil
			} else if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
				response, err := http.Get(arg)
				if err != nil {
					return nil, xerrors.Errorf("Error downloading torrent file: %s", err)
				}

				metaInfo, err := metainfo.Load(response.Body)
				defer response.Body.Close()
				if err != nil {
					return nil, xerrors.Errorf("error loading torrent file %q: %s\n", arg, err)
				}
				t, err := client.AddTorrent(metaInfo)
				if err != nil {
					return nil, xerrors.Errorf("adding torrent: %w", err)
				}
				return t, nil
			} else if strings.HasPrefix(arg, "infohash:") {
				t, _ := client.AddTorrentInfoHash(metainfo.NewHashFromHex(strings.TrimPrefix(arg, "infohash:")))
				return t, nil
			} else {
				metaInfo, err := metainfo.LoadFromFile(arg)
				if err != nil {
					return nil, xerrors.Errorf("error loading torrent file %q: %s\n", arg, err)
				}
				t, err := client.AddTorrent(metaInfo)
				// return nil, xerrors.Errorf("adding torrent: %w", err)
				return t, nil
			}
		}()
		if err != nil {
			log.Printf("RECEIVED TORRERR %s\n", err)
			return xerrors.Errorf("adding torrent for %q: %w", arg, err)
		}
		// torrentBar(t)

		t.AddPeers(func() (ret []torrent.Peer) {
			for _, ta := range flags.TestPeer {
				ret = append(ret, torrent.Peer{
					IP:   ta.IP,
					Port: ta.Port,
				})
			}
			return
		}())
		go func() {
			<-t.GotInfo()
			t.DownloadAll()
		}()
	}
	return nil
}

var flags = struct {
	Mmap                  bool           `help:"memory-map torrent data"`
	TestPeer              []*net.TCPAddr `help:"addresses of some starting peers"`
	Seed                  bool           `help:"seed after download is complete"`
	Addr                  *net.TCPAddr   `help:"network listen addr"`
	UploadRate            tagflag.Bytes  `help:"max piece bytes to send per second"`
	DownloadRate          tagflag.Bytes  `help:"max bytes per second down from peers"`
	Scion                 bool           `help:"Whether to enable a SCION transport"`
	ScionOnly             bool           `help:"Whether to disable TCP/UDP"`
	LocalScionAddr        string         `help:"Local SCION address to use"`
	PeerScionAddrList     []string       `help:"List of remote SCION peers to use"`
	Debug                 bool
	PackedBlocklist       string
	Stats                 *bool
	PublicIP              net.IP
	Progress              bool
	Quiet                 bool     `help:"discard client logging"`
	TCPOnly               bool     `help:"Whether to disable TCP/UDP"`
	UDPOnly               bool     `help:"Whether to disable TCP/UDP"`
	TCPAddrList           []string `help:"List of remote TCP/UDP peers to use"`
	UDPAddrList           []string `help:"List of remote TCP/UDP peers to use"`
	MaxConnectionsPerPeer int
	MaxRequestsPerPeer    int
	PClient               bool
	ReuseFirstPath        bool
	TcpPort               int
	AllowDuplicatePaths   bool
	NumMaxCons            int
	NearestXPercent       int64
	TimeSlotInterval      int64
	PathSelectionType     int64
	PathSelectionFunc     int64
	RunIperfAfterSeconds  int64
	IperfBandwidth        int64
	IperfDuration         int64
	IperfServer           string
	IperfServer2          string
	StorageDir            string
	LAddr                 string
	tagflag.StartPos
	Torrent []string `arity:"+" help:"torrent file path or magnet uri"`
}{
	UploadRate:            -1,
	DownloadRate:          -1,
	Progress:              true,
	Scion:                 false,
	MaxConnectionsPerPeer: 1,
	AllowDuplicatePaths:   false,
	ReuseFirstPath:        false,
	MaxRequestsPerPeer:    250,
	PathSelectionFunc:     -1,
	PathSelectionType:     -1,
	RunIperfAfterSeconds:  -1,
	IperfBandwidth:        0,
	IperfServer:           "",
	IperfServer2:          "",
	IperfDuration:         10,
}

func stdoutAndStderrAreSameFile() bool {
	fi1, _ := os.Stdout.Stat()
	fi2, _ := os.Stderr.Stat()
	return os.SameFile(fi1, fi2)
}

func statsEnabled() bool {
	if flags.Stats == nil {
		return flags.Debug
	}
	return *flags.Stats
}

func exitSignalHandlers(client *torrent.Client) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	for {
		log.Printf("close signal received: %+v", <-c)
		os.Exit(3)
		ctrlcChan <- struct{}{}
		client.Close()
	}
}

func main() {
	if err := mainErr(); err != nil {
		log.Printf("error in main: %v", err)
		os.Exit(1)
	}
}

func ListenQuicTest() error {
	fmt.Println("LISTEN QUIC")
	// serverAddr, err := net.ResolveUDPAddr("udp", "10.0.0.2")
	if err := scion_torrent.InitSQUICCerts(); err != nil {
		return err
	}
	/*laddr, err := net.ResolveUDPAddr("udp", address.String())
	if err != nil {
		return nil, err
	}*/

	conn, err := net.ListenPacket("udp", "10.0.0.2:42428")
	fmt.Printf("LISTEN ON %s\n", "10.0.0.2:42428")
	// conn, err := appnet.ListenPort(uint16(address.Host.Port)) //squic.ListenSCION(nil, address, &quic.Config{KeepAlive: true})
	if err != nil {
		return err
	}

	_, err2 := quic.Listen(conn, scion_torrent.TLSCfg, &quic.Config{KeepAlive: true})
	if err2 != nil {
		return err2
	}

	return nil
}

func DialQuicTest() error {

	fmt.Println("------------------------------")
	if err := scion_torrent.InitSQUICCerts(); err != nil {
		return err
	}
	laddr, err := net.ResolveUDPAddr("udp", "10.0.0.2:42428")
	if err != nil {
		return err
	}

	fmt.Println("LISTEN PACKET")
	conn, err := net.ListenPacket("udp", "10.0.0.1:42428")

	fmt.Println("Dial QUIC")
	if err := scion_torrent.InitSQUICCerts(); err != nil {
		return err
	}

	sess, err := quic.Dial(conn, laddr, "127.0.0.1:42425", scion_torrent.TLSCfg, &quic.Config{
		KeepAlive: true,
	})

	if err != nil {
		return err
	}

	fmt.Println("QUIC SESSION")
	_, err2 := sess.OpenStreamSync(context.Background())
	if err2 != nil {
		return err2
	}
	fmt.Println("------------------------------")
	return nil
}

func runIperf(runIperfAfterSeconds int64, iperfBandwidth int64, iperfDuration int64, iperfServer string, num int) {

	time.Sleep(time.Duration(runIperfAfterSeconds) * time.Second)

	var cmd *exec.Cmd
	startPort := 5401
	// Server
	if iperfServer == "" {
		// cmd = exec.Command("/usr/bin/iperf", "-u", "-s", "-p", fmt.Sprintf("%d", startPort+num))
		cmd = exec.Command("./goben", "-udp", "-readSize=9000", "-connections=6", fmt.Sprintf("-defaultPort=:%d", startPort+num))
	} else { // Client {
		if runIperfAfterSeconds == -1 {
			return
		} // ,
		cmd = exec.Command("./goben", "-udp", "-connections=6", "-passiveServer=true", "-writeSize=9000", fmt.Sprintf("-defaultPort=:%d", startPort+num), "-hosts", iperfServer, fmt.Sprintf("-totalDuration=%ds", iperfDuration))
		// cmd = exec.Command("/usr/bin/iperf", "-u", "-p", fmt.Sprintf("%d", startPort+num), "4", "-c", iperfServer, "-b", fmt.Sprintf("%dm", iperfBandwidth), "-t", strconv.FormatInt(iperfDuration, 10))
	}

	fmt.Println(cmd.Args)

	outfile, err := os.Create(fmt.Sprintf("./iperf-%d.txt", num))
	if err != nil {
		panic(err)
	}
	defer outfile.Close()
	cmd.Stdout = outfile
	cmd.Stderr = outfile
	err = cmd.Start()
	fmt.Println(err)
	err2 := cmd.Wait()
	fmt.Println(err2)
}

func mainErr() error {
	tagflag.Parse(&flags)
	defer envpprof.Stop()
	clientConfig := torrent.NewDefaultClientConfig()
	clientConfig.Debug = flags.Debug
	clientConfig.Seed = flags.Seed
	clientConfig.PublicIp4 = flags.PublicIP
	clientConfig.PublicIp6 = flags.PublicIP
	clientConfig.LAddr = flags.LAddr

	clientConfig.NumMaxCons = flags.NumMaxCons
	clientConfig.NearestXPercent = flags.NearestXPercent
	if flags.TimeSlotInterval > 0 {
		clientConfig.TimeSlotInterval = flags.TimeSlotInterval
	}

	clientConfig.PathSelectionType = flags.PathSelectionType
	clientConfig.PathSelectionFunc = flags.PathSelectionFunc

	if flags.PackedBlocklist != "" {
		blocklist, err := iplist.MMapPackedFile(flags.PackedBlocklist)
		if err != nil {
			return xerrors.Errorf("loading blocklist: %v", err)
		}
		defer blocklist.Close()
		clientConfig.IPBlocklist = blocklist
	}
	if flags.Mmap {
		// clientConfig.DefaultStorage = storage.NewBoltDB("tmp")
		clientConfig.DefaultStorage = storage.NewMMap(flags.StorageDir)
		// clientConfig.DefaultStorage = storage.NewFileByInfoHash("tmp")
	} else {
		// clientConfig.DefaultStorage = storage.NewBoltDB(flags.StorageDir)
	}
	if flags.Addr != nil {
		clientConfig.SetListenAddr(flags.Addr.String())
	}
	if flags.UploadRate != -1 {
		clientConfig.UploadRateLimiter = rate.NewLimiter(rate.Limit(flags.UploadRate), 256<<10)
	}
	if flags.DownloadRate != -1 {
		clientConfig.DownloadRateLimiter = rate.NewLimiter(rate.Limit(flags.DownloadRate), 1<<20)
	}
	if flags.Quiet {
		clientConfig.Logger = log.Discard
	}
	if flags.AllowDuplicatePaths {
		clientConfig.AllowDuplicatePaths = true
	}

	if flags.MaxConnectionsPerPeer > 1 {
		clientConfig.MaxConnectionsPerPeer = flags.MaxConnectionsPerPeer
	}

	if flags.TcpPort > 0 {
		clientConfig.ListenPort = flags.TcpPort
	}

	if flags.MaxRequestsPerPeer > 0 {
		clientConfig.MaxRequestsPerPeer = flags.MaxRequestsPerPeer
	}

	clientConfig.ReuseFirstPath = flags.ReuseFirstPath

	// if !flags.Seed {
	clientConfig.PerformanceBenchmarkClient = flags.PClient
	clientConfig.DisableIPv6 = true
	clientConfig.PerformanceBenchmark = true
	clientConfig.NoDHT = true
	if flags.PClient {
		clientConfig.NoUpload = true
		clientConfig.DisableTrackers = true
		clientConfig.DisablePEX = true
		clientConfig.NoDHT = true
	} else {
		// clientConfig.DisableTrackers = true
		// clientConfig.DisablePEX = true
		// clientConfig.NoUpload = true
		// clientConfig.TorrentPeersHighWater = 1
	}

	// }
	clientConfig.DisableAcceptRateLimiting = true
	if flags.Scion {
		clientConfig.DisableScion = false

		addr, err := snet.ParseUDPAddr(flags.LocalScionAddr)
		if err != nil {
			return err
		}
		clientConfig.PublicScionAddr = addr
		clientConfig.SetScionListenAddr(flags.LocalScionAddr)
		var peers []*snet.UDPAddr
		var sPaths []*snet.Path
		for _, remote := range flags.PeerScionAddrList {
			peerAddr, err := snet.ParseUDPAddr(remote)
			if err != nil {
				fmt.Printf("Failed to parse remote scion addr: %v, %v, ignoring\n", remote, err)
				continue
			}
			paths, err := torrent.GetPathsFromAddr(addr, peerAddr, !clientConfig.AllowDuplicatePaths)
			numPaths := len(paths)

			fmt.Printf("Found %d paths to scion peer %s\n", len(paths), remote)

			if len(paths) > clientConfig.MaxConnectionsPerPeer {
				numPaths = clientConfig.MaxConnectionsPerPeer
			}

			// Use the same path X times
			if clientConfig.ReuseFirstPath && clientConfig.AllowDuplicatePaths {
				numPaths = clientConfig.MaxConnectionsPerPeer
			}

			fmt.Printf("Using %d paths to scion peer %s due to MaxConnectionsPerPeer\n", numPaths, remote)

			for i := 0; i < numPaths; i++ {
				var pathAddr *snet.UDPAddr

				if flags.ReuseFirstPath {
					pathAddr = torrent.ChoosePath(peerAddr, paths[1])
					fmt.Printf("Reusing first path %s to scion peer %s\n", paths[0], remote)
					sPaths = append(sPaths, &paths[0])
				} else {
					pathAddr = torrent.ChoosePath(peerAddr, paths[i])
					fmt.Printf("Using path %s to scion peer %s\n", paths[i], remote)
					fmt.Printf("Fingerprint %s", paths[i].Fingerprint())
					sPaths = append(sPaths, &paths[i])
				}

				peers = append(peers, pathAddr)

			}
		}
		if len(peers) == 0 {
			fmt.Printf("Warning: Scion was enabled, but no valid remote address was given\n")
		}
		clientConfig.RemoteScionAddrs = peers
		clientConfig.RemoteScionPaths = sPaths
		clientConfig.DisableAcceptRateLimiting = true
		clientConfig.DisableTrackers = true
		if flags.ScionOnly {
			clientConfig.DisableTCP = true
			clientConfig.DisableUTP = true
			clientConfig.NoDHT = true

		}
	}
	if flags.TCPOnly {
		clientConfig.DisableScion = true
		clientConfig.DisableUTP = true
		//
		clientConfig.TCPOnly = true

		for _, remote := range flags.TCPAddrList {
			addr, err := net.ResolveTCPAddr("tcp", remote)
			if err != nil {
				fmt.Printf("Failed to parse remote tcp addr: %v, %v, ignoring\n", remote, err)
				continue
			}
			clientConfig.RemoteTCPAddrs = append(clientConfig.RemoteTCPAddrs, addr)

		}
		fmt.Println(clientConfig.RemoteTCPAddrs)
	}

	if flags.UDPOnly {
		clientConfig.DisableScion = true
		clientConfig.DisableTCP = true
		// clientConfig.NoDHT = true
		clientConfig.UDPOnly = true

		fmt.Println("UDP ADDRESSES")
		fmt.Println(flags.UDPAddrList)
		for _, remote := range flags.UDPAddrList {
			addr, err := net.ResolveUDPAddr("udp", remote)
			if err != nil {
				fmt.Printf("Failed to parse remote udp addr: %v, %v, ignoring\n", remote, err)
				continue
			}

			clientConfig.RemoteUDPAddrs = append(clientConfig.RemoteUDPAddrs, addr)
		}
	}

	// if clientConfig.PerformanceBenchmarkClient {
	//	clientConfig.NoDHT = true
	// clientConfig.NoUpload = true
	//	clientConfig.DisablePEX = true
	//	clientConfig.DisableTrackers = true
	// }

	fmt.Println("New Client")
	client, err := torrent.NewClient(clientConfig)
	if err != nil {
		return xerrors.Errorf("creating client: %v", err)
	}
	defer client.Close()
	go exitSignalHandlers(client)

	// Write status on the root path on the default HTTP muxer. This will be bound to localhost
	// somewhere if GOPPROF is set, thanks to the envpprof import.
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		client.WriteStatus(w)
	})
	if stdoutAndStderrAreSameFile() {
		log.Default = log.Logger{log.StreamLogger{W: progress.Bypass(), Fmt: log.LineFormatter}}
	}
	if flags.Progress {
		progress.Start()
	}
	addTorrents(client)
	start := time.Now()
	pid := os.Getpid()
	s := []string{}

	pidsStr, ok := os.LookupEnv("PERF_PIDS")
	if ok {
		s = strings.Split(pidsStr, ",")
	}

	s1 := strconv.FormatInt(int64(pid), 10)
	s = append(s, s1)

	s = Map(s, func(s string) string { return fmt.Sprintf("p-%s", s) })
	fmt.Printf("Calling perf.sh with args %s", s)
	fmt.Println(s)
	s = append([]string{"./perf.sh"}, s...)

	cmd := exec.Command("bash", s...)
	defer cmd.Process.Kill()
	outfile, err := os.Create(fmt.Sprintf("./perf-%s.txt", s1))
	if err != nil {
		panic(err)
	}
	defer outfile.Close()
	cmd.Stdout = outfile
	cmd.Stderr = outfile
	err = cmd.Start()
	fmt.Println(err)
	go func() {
		err2 := cmd.Wait()
		fmt.Println(err2)
	}()

	/*if flags.Seed {
		err := ListenQuicTest()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	} else {
		err := DialQuicTest()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}*/

	go runIperf(flags.RunIperfAfterSeconds, flags.IperfBandwidth, flags.IperfDuration, flags.IperfServer, 1)
	go runIperf(flags.RunIperfAfterSeconds, flags.IperfBandwidth, flags.IperfDuration, flags.IperfServer2, 2)
	if client.WaitAll() {
		elapsed := time.Since(start)
		log.Printf("Binomial took %s", elapsed)
		log.Print("downloaded ALL the torrents")

	} else {
		return xerrors.New("y u no complete torrents?!")
	}
	if flags.Seed {
		outputStats(client)
		select {
		case <-ctrlcChan:
			break
		}
	}
	outputStats(client)
	return nil
}

func outputStats(cl *torrent.Client) {
	if !statsEnabled() {
		return
	}
	expvar.Do(func(kv expvar.KeyValue) {
		fmt.Printf("%s: %s\n", kv.Key, kv.Value)
	})
	cl.WriteStatus(os.Stdout)
}
