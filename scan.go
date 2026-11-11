package portscan

import (
	"context"
	"errors"
	"net"
	"sync"
)

type scanJob struct {
	host string
	ip   net.IP
	port uint16
}

func (s *Scanner) Scan(
	ctx context.Context,
	hosts []string,
	ports []uint16,
) (<-chan Result, error) {

	if ctx == nil {
		return nil, errors.New("nil context")
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if len(hosts) == 0 || len(ports) == 0 {
		return nil, errors.New("hosts and ports must not be empty")
	}

	targets, err := resolveTargetsWithLookup(ctx, hosts, s.lookupIP)
	if err != nil {
		return nil, err
	}

	uniquePorts := make([]uint16, 0, len(ports))
	seenPorts := make(map[uint16]struct{})

	for _, port := range ports {
		if port == 0 {
			return nil, errors.New("port 0 is not allowed")
		}

		if _, exists := seenPorts[port]; exists {
			continue
		}

		seenPorts[port] = struct{}{}
		uniquePorts = append(uniquePorts, port)
	}

	jobs := make(chan scanJob)
	results := make(chan Result)

	var wg sync.WaitGroup

	workers := s.concurrency

	if len(targets) <= workers/len(uniquePorts) {
		workers = len(targets) * len(uniquePorts)
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for {
				select {
				case <-ctx.Done():
					return

				case job, ok := <-jobs:
					if !ok {
						return
					}

					if ctx.Err() != nil {
						return
					}

					select {
					case s.slots <- struct{}{}:
					case <-ctx.Done():
						return
					}

					if ctx.Err() != nil {
						<-s.slots
						return
					}

					result := s.checkPort(
						ctx,
						job.host,
						job.ip,
						job.port,
					)

					<-s.slots

					select {
					case results <- result:
					case <-ctx.Done():
						return
					}

				}
			}
		}()
	}

	go func() {
		defer close(jobs)

		for _, target := range targets {
			for _, port := range uniquePorts {
				if ctx.Err() != nil {
					return
				}

				job := scanJob{
					host: target.host,
					ip:   target.ip,
					port: port,
				}

				select {
				case jobs <- job:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	return results, nil
}
