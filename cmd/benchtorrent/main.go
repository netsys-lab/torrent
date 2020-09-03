// Downloads torrents from the command-line.
package main

import (
	"expvar"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/scionproto/scion/go/lib/snet"

	"golang.org/x/xerrors"

	"github.com/anacrolix/log"

	"github.com/anacrolix/envpprof"
	"github.com/anacrolix/tagflag"
	"github.com/anacrolix/torrent"
	"github.com/anacrolix/torrent/iplist"
	"github.com/anacrolix/torrent/metainfo"
	"github.com/anacrolix/torrent/storage"
	humanize "github.com/dustin/go-humanize"
	"github.com/gosuri/uiprogress"

	// "github.com/netsec-ethz/scion-apps/pkg/appnet"
	"golang.org/x/time/rate"
)

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

func mainErr() error {
	tagflag.Parse(&flags)
	defer envpprof.Stop()
	clientConfig := torrent.NewDefaultClientConfig()
	clientConfig.Debug = flags.Debug
	clientConfig.Seed = flags.Seed
	clientConfig.PublicIp4 = flags.PublicIP
	clientConfig.PublicIp6 = flags.PublicIP
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
		clientConfig.DefaultStorage = storage.NewMMap("tmp")
		// clientConfig.DefaultStorage = storage.NewFileByInfoHash("tmp")
	}
	if flags.Addr != nil {
		clientConfig.SetListenAddr(flags.Addr.String())
	}
	if flags.UploadRate != -1 {
		clientConfig.UploadRateLimiter = rate.NewLimiter(rate.Limit(flags.UploadRate), 256<<10) // TMPCHANGE 10
	}
	if flags.DownloadRate != -1 {
		clientConfig.DownloadRateLimiter = rate.NewLimiter(rate.Limit(flags.DownloadRate), 1<<20) // TMPCHANGE 20
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

			fmt.Printf("Using %d paths to scion peer %s due to MaxConnectionsPerPeer\n", numPaths, remote)

			for i := 0; i < numPaths; i++ {
				pathAddr := torrent.ChoosePath(peerAddr, paths[i])

				if flags.ReuseFirstPath {
					pathAddr = torrent.ChoosePath(peerAddr, paths[0])
					fmt.Printf("Reusing first path %s to scion peer %s\n", paths[0], remote)
				} else {
					fmt.Printf("Using path %s to scion peer %s\n", paths[i], remote)
					fmt.Printf("Fingerprint %s", paths[i].Fingerprint())
				}

				peers = append(peers, pathAddr)
				sPaths = append(sPaths, &paths[i])
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
