package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
)

type scanTarget struct {
	host string
	ip   net.IP
}

func resolveTargets(ctx context.Context, hosts []string) ([]scanTarget, error) {
	return resolveTargetsWithLookup(ctx, hosts, net.DefaultResolver.LookupIPAddr)
}

func resolveTargetsWithLookup(
	ctx context.Context,
	hosts []string,
	lookup func(context.Context, string) ([]net.IPAddr, error),
) ([]scanTarget, error) {
	targets := make([]scanTarget, 0, len(hosts))
	seenHosts := make(map[string]struct{}, len(hosts))

	for _, rawHost := range hosts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		host := strings.TrimSpace(rawHost)

		if host == "" {
			return nil, errors.New("host must not be empty")
		}

		ip := net.ParseIP(host)
		key := strings.ToLower(host)

		if ip != nil {
			key = ip.String()
		}

		if _, exists := seenHosts[key]; exists {
			continue
		}

		seenHosts[key] = struct{}{}

		if ip != nil {
			targets = append(targets, scanTarget{
				host: host,
				ip:   ip,
			})
			continue
		}

		ips, err := lookup(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve host %q: %w", host, err)
		}

		if len(ips) == 0 {
			return nil, fmt.Errorf("no IP addresses for host %q", host)
		}

		seenIPs := make(map[string]struct{}, len(ips))

		for _, addr := range ips {
			if addr.IP == nil {
				continue
			}

			ipKey := addr.IP.String()

			if _, exists := seenIPs[ipKey]; exists {
				continue
			}

			seenIPs[ipKey] = struct{}{}

			targets = append(targets, scanTarget{
				host: host,
				ip:   addr.IP,
			})
		}

		if len(seenIPs) == 0 {
			return nil, fmt.Errorf("no valid IP addresses for host %q", host)
		}
	}

	return targets, nil
}
