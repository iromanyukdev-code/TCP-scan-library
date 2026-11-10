package portscan

import "fmt"

type Ports struct {
	values []uint16
	err    error
}

func List(ports ...int) Ports {
	p := Ports{}
	seen := make(map[uint16]bool)
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return Ports{err: fmt.Errorf("port %d: must be between 1 and 65535", port)}
		}
		v := uint16(port)
		if !seen[v] {
			seen[v] = true
			p.values = append(p.values, v)
		}
	}
	return p
}

func Range(first, last int) Ports {
	if first < 1 || last > 65535 || first > last {
		return Ports{err: fmt.Errorf("invalid port range %d-%d", first, last)}
	}
	p := Ports{values: make([]uint16, 0, last-first+1)}
	for n := first; n <= last; n++ {
		p.values = append(p.values, uint16(n))
	}
	return p
}

func Union(sets ...Ports) Ports {
	p := Ports{}
	seen := make(map[uint16]bool)
	for _, set := range sets {
		if set.err != nil {
			return Ports{err: set.err}
		}
		for _, v := range set.values {
			if !seen[v] {
				seen[v] = true
				p.values = append(p.values, v)
			}
		}
	}
	return p
}
