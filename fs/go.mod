module github.com/anacrolix/torrent/fs

go 1.12

require (
	bazil.org/fuse v0.0.0-20180421153158-65cc252bf669
	github.com/anacrolix/envpprof v1.0.0
	github.com/anacrolix/missinggo v1.1.1
	github.com/anacrolix/tagflag v0.0.0-20180803105420-3a8ff5428f76
	github.com/anacrolix/torrent v1.5.1
	github.com/fsnotify/fsnotify v1.4.7
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7 // indirect
	github.com/stretchr/testify v1.3.0
)

replace github.com/anacrolix/torrent => ../
