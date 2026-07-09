package scanner

import (
	"context"
	"sync"
	"sync/atomic"
)

type ScanJob struct {
	Host string
	Port int
}

type Pool struct {
	workers    int
	jobs       chan ScanJob
	results    chan PortResult
	workersWg  sync.WaitGroup
	scanned    atomic.Int64
	totalScans int64
}

func NewPool(workers int, totalJobs int) *Pool {
	return &Pool{
		workers:    workers,
		jobs:       make(chan ScanJob, workers*2),
		results:    make(chan PortResult, workers*2),
		totalScans: int64(totalJobs),
	}
}

func (p *Pool) Start(ctx context.Context) {
	for i := 0; i < p.workers; i++ {
		p.workersWg.Add(1)
		go p.worker(ctx)
	}
}

func (p *Pool) worker(ctx context.Context) {
	defer p.workersWg.Done()
	for job := range p.jobs {
		select {
		case <-ctx.Done():
			return
		default:
		}

		result := ScanPort(ctx, job.Host, job.Port)
		p.scanned.Add(1)
		p.results <- result
	}
}

func (p *Pool) Submit(host string, port int) {
	p.jobs <- ScanJob{Host: host, Port: port}
}

func (p *Pool) Close() {
	close(p.jobs)
}

func (p *Pool) Results() <-chan PortResult {
	return p.results
}

func (p *Pool) Wait() {
	p.workersWg.Wait()
	close(p.results)
}

func (p *Pool) Progress() float64 {
	if p.totalScans == 0 {
		return 0
	}
	return float64(p.scanned.Load()) / float64(p.totalScans)
}
