package engine

import (
	"sync"
	"time"

	"trendify-scanner/internal/parser"
	"trendify-scanner/internal/prober"
)

type Engine struct {
	Workers int

	Timeout time.Duration
}

func New(
	workers int,
	timeout time.Duration,
) *Engine {

	if workers <= 0 {
		workers = 100
	}

	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	return &Engine{
		Workers: workers,
		Timeout: timeout,
	}
}

func (e *Engine) Scan(
	ips []string,
	cfg *parser.VLESSConfig,
) []prober.Result {

	if len(ips) == 0 || cfg == nil {
		return []prober.Result{}
	}

	workers := e.Workers

	if workers > len(ips) {
		workers = len(ips)
	}

	jobs := make(chan string)
	results := make(chan prober.Result)

	var wg sync.WaitGroup

	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()

			for ip := range jobs {
				result := prober.Probe(
					ip,
					cfg,
					e.Timeout,
				)

				results <- result
			}
		}()
	}

	go func() {
		for _, ip := range ips {
			jobs <- ip
		}

		close(jobs)

		wg.Wait()

		close(results)
	}()

	output := make(
		[]prober.Result,
		0,
		len(ips),
	)

	for result := range results {
		output = append(
			output,
			result,
		)
	}

	return output
}
