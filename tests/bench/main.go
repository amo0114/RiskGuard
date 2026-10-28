// bench measures added latency of the Guard versus direct New API (C08): it fires the same
// chat requests at two base URLs with fixed concurrency and prints p50/p95/p99 per target.
//
//	go run ./tests/bench -direct http://127.0.0.1:14000 -guard http://127.0.0.1:14100 -n 2000 -c 16 -body-kb 200
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

func main() {
	direct := flag.String("direct", "", "direct base URL")
	guard := flag.String("guard", "", "guard base URL")
	n := flag.Int("n", 1000, "requests per target")
	c := flag.Int("c", 8, "concurrency")
	bodyKB := flag.Int("body-kb", 100, "approximate request body size")
	unique := flag.Bool("unique", true, "make every user turn unique (defeats the classifier cache)")
	flag.Parse()

	for _, t := range []struct{ name, url string }{{"direct", *direct}, {"guard", *guard}} {
		if t.url == "" {
			continue
		}
		lat, errs, wall := run(t.url+"/v1/chat/completions", *n, *c, *bodyKB, *unique)
		sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
		q := func(p float64) time.Duration { return lat[int(p*float64(len(lat)-1))] }
		fmt.Printf("%-6s n=%d errors=%d rps=%.0f p50=%v p95=%v p99=%v max=%v\n", t.name, len(lat), errs,
			float64(len(lat))/wall.Seconds(), q(.5).Round(time.Microsecond), q(.95).Round(time.Microsecond),
			q(.99).Round(time.Microsecond), lat[len(lat)-1].Round(time.Microsecond))
	}
}

func run(url string, n, c, bodyKB int, unique bool) ([]time.Duration, int, time.Duration) {
	history := strings.Repeat("previous turn text ", bodyKB*1024/19)
	client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: c, Proxy: nil}}
	var mu sync.Mutex
	var lat []time.Duration
	errs := 0
	jobs := make(chan int)
	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < c; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				q := "summarise the build log"
				if unique {
					q = fmt.Sprintf("%s #%d", q, i)
				}
				b, _ := json.Marshal(map[string]any{"model": "m", "messages": []map[string]string{
					{"role": "user", "content": history}, {"role": "assistant", "content": "ok"}, {"role": "user", "content": q}}})
				t0 := time.Now()
				resp, err := client.Post(url, "application/json", bytes.NewReader(b))
				d := time.Since(t0)
				mu.Lock()
				if err != nil || resp.StatusCode >= 500 {
					errs++
				} else {
					lat = append(lat, d)
				}
				mu.Unlock()
				if err == nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}
		}()
	}
	for i := 0; i < n; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return lat, errs, time.Since(start)
}
