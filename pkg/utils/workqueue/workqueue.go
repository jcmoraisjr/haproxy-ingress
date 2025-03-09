package workqueue

import (
	"context"
	"time"

	"golang.org/x/sync/errgroup"
	"k8s.io/client-go/util/workqueue"
)

type Options struct {
	// Workers defines the number of worker threads, defaults to 1 if not declared
	Workers int
}

type SyncCallback[T comparable] func(context.Context, T) error

func New[T comparable](sync SyncCallback[T], rateLimiter workqueue.TypedRateLimiter[T], opts ...Options) *WorkQueue[T] {
	opt := Options{}
	if len(opts) > 0 {
		opt = opts[0]
	}
	if rateLimiter == nil {
		rateLimiter = workqueue.DefaultTypedControllerRateLimiter[T]()
	}
	return &WorkQueue[T]{
		queue:   workqueue.NewTypedRateLimitingQueue(rateLimiter),
		sync:    sync,
		workers: max(opt.Workers, 1),
	}
}

type WorkQueue[T comparable] struct {
	queue   workqueue.TypedRateLimitingInterface[T]
	sync    SyncCallback[T]
	workers int
}

func (w *WorkQueue[T]) Start(ctx context.Context) error {
	group := errgroup.Group{}

	group.Go(func() error {
		<-ctx.Done()
		w.queue.ShutDown()
		return nil
	})

	for range w.workers {
		group.Go(func() error {
			for w.process(ctx) {
			}
			return nil
		})
	}

	return group.Wait()
}

func (w *WorkQueue[T]) Add(item T) {
	w.queue.AddRateLimited(item)
}

func (w *WorkQueue[T]) AddAfter(item T, duration time.Duration) {
	w.queue.AddAfter(item, duration)
}

func (w *WorkQueue[T]) Remove(item T) {
	w.queue.Forget(item)
	w.queue.Done(item)
}

func (w *WorkQueue[T]) Len() int {
	return w.queue.Len()
}

func (w *WorkQueue[T]) process(ctx context.Context) bool {
	item, shutdown := w.queue.Get()
	if shutdown {
		return false
	}

	defer w.queue.Done(item)

	if err := w.sync(ctx, item); err != nil {
		w.queue.AddRateLimited(item)
		return true
	}

	w.queue.Forget(item)
	return true
}
