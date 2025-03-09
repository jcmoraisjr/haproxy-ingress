package workqueue_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils/workqueue"
	"github.com/stretchr/testify/require"
)

func TestQueue(t *testing.T) {
	type event struct {
		id    string
		delay time.Duration
	}

	start := time.Now()

	var actualEvents []event
	var mu sync.Mutex
	q := workqueue.New(func(ctx context.Context, obj string) error {
		mu.Lock()
		defer mu.Unlock()
		actualEvents = append(actualEvents, event{
			id:    obj,
			delay: time.Since(start),
		})
		return nil
	}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = q.Start(ctx)
		close(done)
	}()

	q.Add("1")
	q.Add("1")
	q.Add("2")
	q.Add("2")

	time.Sleep(500 * time.Millisecond)
	q.Add("1")
	q.Add("1")
	q.Add("3")
	q.Add("3")

	time.Sleep(1500 * time.Millisecond)
	q.Add("2")
	q.Add("2")
	q.Add("3")
	q.Add("3")

	time.Sleep(2 * time.Second)
	cancel()

	select {
	case <-ctx.Done():
	case <-time.After(10 * time.Second):
		require.Fail(t, "queue shutdown timed out")
	}

}
