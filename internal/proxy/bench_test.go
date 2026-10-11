package proxy

import (
	"io"
	"net/http"
	"slices"
	"testing"
	"time"
)

func benchmarkHTTP(b *testing.B, tunnel bool) {
	f := fullProxy(b)
	client := f.client
	target := f.url + "/apps/payroll/report"
	if !tunnel {
		transport := &http.Transport{}
		b.Cleanup(transport.CloseIdleConnections)
		client = &http.Client{Transport: transport, Timeout: 3 * time.Second}
		target = f.direct + "/report"
	}
	request := func() {
		req, err := http.NewRequest("GET", target, nil)
		if err != nil {
			b.Fatal(err)
		}
		req.Header.Set("X-Device-Posture", `{"disk_encrypted":true,"firewall_on":true}`)
		req.Header.Set("X-Perimeter-User", "aisha")
		req.Header.Set("X-Perimeter-Group", "finance")
		response, err := client.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		_, readErr := io.Copy(io.Discard, response.Body)
		closeErr := response.Body.Close()
		if readErr != nil {
			b.Fatal(readErr)
		}
		if closeErr != nil {
			b.Fatal(closeErr)
		}
		if response.StatusCode != 200 {
			b.Fatalf("status %d", response.StatusCode)
		}
	}
	for i := 0; i < 10; i++ {
		request()
	}
	samples := make([]int64, 0, b.N)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		request()
		samples = append(samples, time.Since(start).Nanoseconds())
	}
	b.StopTimer()
	slices.Sort(samples)
	b.ReportMetric(float64(samples[len(samples)/2])/1000, "p50-us")
	b.ReportMetric(float64(samples[(len(samples)-1)*99/100])/1000, "p99-us")
}
func BenchmarkHTTPDirect(b *testing.B) { benchmarkHTTP(b, false) }
func BenchmarkHTTPTunnel(b *testing.B) { benchmarkHTTP(b, true) }
