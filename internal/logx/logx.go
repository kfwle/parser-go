// Package logx provides thread-safe console output, progress bars and a
// context-aware worker pool shared by every parser stage.
package logx

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	mu      sync.Mutex
	out     io.Writer = os.Stdout
	verbose           = true
)

// SetVerbose toggles verbose messages.
func SetVerbose(v bool) {
	mu.Lock()
	defer mu.Unlock()
	verbose = v
}

// Verbose reports the current verbosity.
func Verbose() bool {
	mu.Lock()
	defer mu.Unlock()
	return verbose
}

// SetOutput replaces the underlying writer (useful in tests).
func SetOutput(w io.Writer) {
	mu.Lock()
	defer mu.Unlock()
	out = w
}

// Printf writes a formatted line atomically.
func Printf(format string, args ...any) {
	mu.Lock()
	defer mu.Unlock()
	fmt.Fprintf(out, format, args...)
}

// Println writes a line atomically.
func Println(args ...any) {
	mu.Lock()
	defer mu.Unlock()
	fmt.Fprintln(out, args...)
}

// Verbosef prints only when verbose mode is enabled.
func Verbosef(format string, args ...any) {
	mu.Lock()
	defer mu.Unlock()
	if verbose {
		fmt.Fprintf(out, format, args...)
	}
}

// Infof is an alias used for important messages.
func Infof(format string, args ...any) { Printf(format, args...) }

func clearLineLocked() {
	if runtime.GOOS == "windows" {
		fmt.Fprint(out, "\r"+strings.Repeat(" ", 110)+"\r")
		return
	}
	fmt.Fprint(out, "\r\033[K")
}

// Progress renders a single-line progress bar, intended for short updates.
func Progress(current, total int, prefix, suffix string) {
	mu.Lock()
	defer mu.Unlock()
	clearLineLocked()
	pct := 0.0
	filled := 0
	if total > 0 {
		pct = float64(current) / float64(total) * 100
		filled = 20 * current / total
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", 20-filled)
	fmt.Fprintf(out, "%s|%s| %3.0f%% %d/%d %s", prefix, bar, pct, current, total, suffix)
}

// ClearLine removes the current progress line.
func ClearLine() {
	mu.Lock()
	defer mu.Unlock()
	clearLineLocked()
}

// RunPool executes fn for every item using a fixed number of workers and shows
// a progress bar. It returns the number of processed items. The context is
// checked before every task, so Ctrl+C stops the stage promptly.
func RunPool[T any](ctx context.Context, items []T, workers int, desc string, fn func(context.Context, T)) int {
	total := len(items)
	if total == 0 {
		return 0
	}
	if workers < 1 {
		workers = 1
	}
	if workers > total {
		workers = total
	}

	jobs := make(chan T)
	var done atomic.Int64
	var wg sync.WaitGroup
	start := time.Now()

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				if ctx.Err() != nil {
					continue
				}
				fn(ctx, item)
				done.Add(1)
			}
		}()
	}

	finished := make(chan struct{})
	go func() {
		defer close(finished)
		for _, item := range items {
			select {
			case jobs <- item:
			case <-ctx.Done():
				close(jobs)
				return
			}
		}
		close(jobs)
	}()

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	waitDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitDone)
	}()

loop:
	for {
		select {
		case <-waitDone:
			break loop
		case <-ctx.Done():
			// Drain the feeder and wait for in-flight tasks.
			<-finished
			<-waitDone
			break loop
		case <-ticker.C:
			d := int(done.Load())
			elapsed := time.Since(start).Seconds()
			speed := 0.0
			if elapsed > 0 {
				speed = float64(d) / elapsed
			}
			Progress(d, total, desc, fmt.Sprintf("%.0f/сек %.0fс", speed, elapsed))
		}
	}

	ClearLine()
	elapsed := time.Since(start)
	Printf("%s: %d/%d за %.1fс\n", desc, done.Load(), total, elapsed.Seconds())
	return int(done.Load())
}

// Bar is a simple reusable bytes progress bar for downloads.
type Bar struct {
	mu       sync.Mutex
	label    string
	total    int64
	written  int64
	lastDraw time.Time
}

// NewBar creates a download progress bar.
func NewBar(label string, total int64) *Bar { return &Bar{label: label, total: total} }

// Add updates progress; drawing is throttled to 10 fps.
func (b *Bar) Add(n int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.written += n
	if time.Since(b.lastDraw) < 100*time.Millisecond && b.written != b.total {
		return
	}
	b.lastDraw = time.Now()
	mu.Lock()
	defer mu.Unlock()
	clearLineLocked()
	if b.total > 0 {
		pct := float64(b.written) / float64(b.total) * 100
		filled := int(30 * b.written / b.total)
		if filled > 30 {
			filled = 30
		}
		fmt.Fprintf(out, "  %s |%s%s| %.1f%% (%d/%d KB)", b.label,
			strings.Repeat("█", filled), strings.Repeat("░", 30-filled),
			pct, b.written/1024, b.total/1024)
	} else {
		fmt.Fprintf(out, "  %s: %d KB", b.label, b.written/1024)
	}
}

// Finish clears the progress line.
func (b *Bar) Finish() {
	b.mu.Lock()
	defer b.mu.Unlock()
	mu.Lock()
	defer mu.Unlock()
	clearLineLocked()
}
