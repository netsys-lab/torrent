package torrent

import "github.com/anacrolix/missinggo"

type ipPortAddr struct {
	ipp missinggo.IpPort
}

func (ipp *ipPortAddr) Network() string {
	if len(ipp.ipp.IP) == 4 {
		return "udptcp4"
	} else if len(ipp.ipp.IP) == 16 {
		return "udptcp6"
	}
	return ""
}

func (ipp *ipPortAddr) String() string {
	return ipp.ipp.String()
}
