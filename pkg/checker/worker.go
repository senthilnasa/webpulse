package checker

import (
	"context"
	"sync"
)

// Job represents a single URL checking task.
type Job struct {
	Index int
	URL   string
}

// WorkerPool manages parallel execution of URL checking tasks using a bounded pool of goroutines.
type WorkerPool struct {
	workers int
	checker *HTTPChecker
}

// NewWorkerPool instantiates a WorkerPool.
func NewWorkerPool(workers int, checker *HTTPChecker) *WorkerPool {
	if workers <= 0 {
		workers = 10
	}
	return &WorkerPool{
		workers: workers,
		checker: checker,
	}
}

// Run distributes URL validation tasks across N worker goroutines and collects results.
func (p *WorkerPool) Run(ctx context.Context, urls []string, collector *ResultCollector) {
	totalJobs := len(urls)
	if totalJobs == 0 {
		return
	}

	jobsChan := make(chan Job, totalJobs)
	for i, u := range urls {
		jobsChan <- Job{Index: i, URL: u}
	}
	close(jobsChan)

	numWorkers := p.workers
	if numWorkers > totalJobs {
		numWorkers = totalJobs
	}

	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobsChan {
				select {
				case <-ctx.Done():
					return
				default:
				}

				res := p.checker.CheckURL(ctx, job.URL)
				collector.Add(res)
			}
		}()
	}

	wg.Wait()
}
