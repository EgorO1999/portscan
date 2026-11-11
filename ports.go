package portscan

import (
	"errors"
	"fmt"
)

func Ports(values ...int) ([]uint16, error) {
	if len(values) == 0 {
		return nil, errors.New("ports list must not be empty")
	}

	ports := make([]uint16, 0, len(values))

	for _, value := range values {
		if value < 1 || value > 65535 {
			return nil, fmt.Errorf("invalid port: %d", value)
		}

		ports = append(ports, uint16(value))
	}

	return ports, nil
}

func Range(start, end int) ([]uint16, error) {
	if start < 1 || start > 65535 || end < 1 || end > 65535 {
		return nil, fmt.Errorf("invalid port range: %d-%d", start, end)
	}

	if start > end {
		return nil, fmt.Errorf("reversed port range: %d-%d", start, end)
	}

	ports := make([]uint16, 0, end-start+1)

	for port := start; port <= end; port++ {
		ports = append(ports, uint16(port))
	}

	return ports, nil
}

func Union(groups ...[]uint16) []uint16 {
	var result []uint16
	seen := make(map[uint16]struct{})

	for _, group := range groups {
		for _, port := range group {
			if _, exists := seen[port]; exists {
				continue
			}

			seen[port] = struct{}{}
			result = append(result, port)
		}
	}

	return result
}
