module github.com/anacrolix/torrent

require (
	bazil.org/fuse v0.0.0-20180421153158-65cc252bf669
	github.com/BurntSushi/toml v0.3.1 // indirect
	github.com/alexflint/go-arg v1.1.0
	github.com/anacrolix/dht/v2 v2.0.5-0.20190913023154-c5780a290ed6
	github.com/anacrolix/envpprof v1.0.1
	github.com/anacrolix/go-libutp v1.0.2
	github.com/anacrolix/log v0.3.1-0.20191001111012-13cede988bcd
	github.com/anacrolix/missinggo v1.2.1
	github.com/anacrolix/missinggo/perf v1.0.0
	github.com/anacrolix/sync v0.2.0
	github.com/anacrolix/tagflag v1.0.1
	github.com/anacrolix/upnp v0.1.1
	github.com/anacrolix/utp v0.0.0-20180219060659-9e0e1d1d0572
	github.com/antlr/antlr4 v0.0.0-20191011202612-ad2bd05285ca // indirect
	github.com/bifurcation/mint v0.0.0-20180224182115-30a67d8540b4 // indirect
	github.com/boltdb/bolt v1.3.1
	github.com/bradfitz/iter v0.0.0-20190303215204-33e6a9893b0c
	github.com/davecgh/go-spew v1.1.1
	github.com/dustin/go-humanize v1.0.0
	github.com/edsrzf/mmap-go v1.0.0
	github.com/fsnotify/fsnotify v1.4.7
	github.com/google/btree v1.0.0
	github.com/google/gopacket v1.1.17 // indirect
	github.com/gosuri/uiprogress v0.0.1
	github.com/hashicorp/golang-lru v0.5.3 // indirect
	github.com/inconshreveable/log15 v0.0.0-20180818164646-67afb5ed74ec // indirect
	github.com/jessevdk/go-flags v1.4.0
	github.com/lucas-clemente/aes12 v0.0.0-20171027163421-cd47fb39b79f // indirect
	github.com/lucas-clemente/quic-go v0.8.0
	github.com/lucas-clemente/quic-go-certificates v0.0.0-20160823095156-d2f86524cced // indirect
	github.com/marten-seemann/qpack v0.1.0 // indirect
	github.com/mattn/go-colorable v0.1.4 // indirect
	github.com/mattn/go-sqlite3 v1.10.0
	github.com/netsec-ethz/scion-apps v0.1.0
	github.com/pierrec/xxHash v0.1.5 // indirect
	github.com/pkg/errors v0.8.2-0.20190227000051-27936f6d90f9
	github.com/prometheus/client_golang v1.2.0 // indirect
	github.com/scionproto/scion v0.5.0
	github.com/stretchr/testify v1.4.0
	golang.org/x/net v0.0.0-20191105084925-a882066a44e0
	golang.org/x/time v0.0.0-20190308202827-9d24e82272b4
	golang.org/x/xerrors v0.0.0-20190717185122-a985d3407aa7
	gopkg.in/natefinch/lumberjack.v2 v2.0.0 // indirect
	gopkg.in/restruct.v1 v1.0.0-20190323193435-3c2afb705f3c // indirect
	zombiezen.com/go/capnproto2 v2.17.0+incompatible // indirect
)

go 1.13

replace github.com/boltdb/bolt => github.com/etcd-io/bbolt v1.3.3

// replace github.com/scionproto/scion => github.com/matzf/scion v0.2.1-0.20190724102211-486e005da176
