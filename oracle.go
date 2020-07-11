package torrent

import (
	"context"
	"fmt"

	"github.com/netsec-ethz/scion-apps/pkg/appnet"
	"github.com/scionproto/scion/go/lib/snet"
)

func unique(pathSlice []snet.Path) []snet.Path {
	keys := make(map[string]bool)
	list := []snet.Path{}
	for _, entry := range pathSlice {
		if _, value := keys[fmt.Sprintf("%s", entry)]; !value {
			keys[fmt.Sprintf("%s", entry)] = true
			list = append(list, entry)
		}
	}
	return list
}

func GetPathsFromAddr(lAddr, rAddr *snet.UDPAddr, shouldBeUnique bool) ([]snet.Path, error) {

	if !lAddr.IA.Equal(rAddr.IA) {

		// query paths from here to there:
		pathSet, err := appnet.DefNetwork().PathQuerier.Query(context.Background(), rAddr.IA)
		if err != nil {
			return nil, err
		}

		if len(pathSet) == 0 {
			return nil, fmt.Errorf("No Paths")
		}
		// print all paths. Also pick one path. Here we chose the path with least hops:
		i := 0
		fmt.Println("Available paths:")
		for _, path := range pathSet {
			fmt.Printf("[%2d] %d %s\n", i, len(path.Interfaces())/2, path)
		}

		if !shouldBeUnique {
			return pathSet, nil
		}

		uniquePaths := unique(pathSet)
		fmt.Println("Unique paths:")
		for _, path := range uniquePaths {
			fmt.Printf("[%2d] %d %s\n", i, len(path.Interfaces())/2, path)
		}

		return uniquePaths, nil
	}

	return []snet.Path{}, nil
}

func ChoosePath(rAddr *snet.UDPAddr, path snet.Path) *snet.UDPAddr {
	// we need to copy the path to the destination (destination is the whole selected path)
	newAddr := rAddr.Copy()
	newAddr.Path = path.Path()
	newAddr.Path.InitOffsets()
	newAddr.NextHop = path.OverlayNextHop()

	return newAddr
}
