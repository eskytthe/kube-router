package utils

import (
	"github.com/golang/glog"
	"sync"
	"time"
)

type Queue struct {
	sync.Mutex
	items []*QueueItem
}

type QueueItem struct {
	Identifier string
	Todo       func() error
	Callback   func(err error)
}

func (q *Queue) Push(item *QueueItem) {
	q.Lock()
	glog.V(1).Info("Queue content before push: {}", q.items)
	defer q.Unlock()

	length := len(q.items)
	if length > 0 {
		last := q.items[length-1]
		if last != nil && item.Identifier == last.Identifier {
			glog.V(1).Info("Ignoring repeated action put on queue: {}", item.Identifier)
			return
		}
	}

	q.items = append(q.items, item)
	glog.V(1).Info("Queue content after push: {}", q.items)
}

func (q *Queue) Pop() *QueueItem {
	q.Lock()
	glog.V(1).Info("Queue content before pop: {}", q.items)
	defer q.Unlock()
	if len(q.items) == 0 {
		return nil
	}
	item := q.items[0]
	q.items = q.items[1:]
	glog.V(1).Info("Queue content after pop: {}", q.items)
	return item
}

func NewQueue() *Queue {
	return &Queue{
		items: make([]*QueueItem, 0),
	}
}

func (q *Queue) Run(stopCh chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	glog.V(1).Info("Starting queue handler...")
	return
	// loop forever till notified to stop on stopCh
	for {
		select {
		case <-stopCh:
			glog.V(1).Info("Shutting down queue handler")
			return
		default:
			time.Sleep(400 * time.Millisecond)
		}
		item := q.Pop()
		if item != nil {
			now := time.Now()
			item.Callback(item.Todo())
			glog.V(1).Info("Processed queue item: {}, in time: {}", item, time.Since(now))
		}
	}

}
