package cluster

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
)

// DefaultVirtualPoints is how many ring positions each set gets.
const DefaultVirtualPoints = 128

// Ring is a consistent-hash ring over named sets. Adding a set moves only
// the keys that now fall to it; no key moves between the existing sets.
type Ring struct {
	points []point
	ids    []string
}

type point struct {
	hash uint64
	set  int // index into ids
}

func hash64(s string) uint64 {
	sum := sha256.Sum256([]byte(s))
	return binary.BigEndian.Uint64(sum[:8])
}

// NewRing builds a ring over the given set IDs with vpoints positions each
// (0 means DefaultVirtualPoints).
func NewRing(ids []string, vpoints int) *Ring {
	if vpoints <= 0 {
		vpoints = DefaultVirtualPoints
	}
	r := &Ring{ids: append([]string(nil), ids...)}
	for i, id := range ids {
		for v := 0; v < vpoints; v++ {
			r.points = append(r.points, point{hash64(fmt.Sprintf("%s#%d", id, v)), i})
		}
	}
	sort.Slice(r.points, func(a, b int) bool {
		if r.points[a].hash != r.points[b].hash {
			return r.points[a].hash < r.points[b].hash
		}
		return r.points[a].set < r.points[b].set
	})
	return r
}

// Len is the number of sets on the ring.
func (r *Ring) Len() int { return len(r.ids) }

// Locate returns the index (into the ids given to NewRing) of the set that
// owns bucket/object.
func (r *Ring) Locate(bucket, object string) int {
	if len(r.points) == 0 {
		return -1
	}
	h := hash64(bucket + "\x00" + object)
	i := sort.Search(len(r.points), func(i int) bool { return r.points[i].hash >= h })
	if i == len(r.points) {
		i = 0
	}
	return r.points[i].set
}
