package priority_queue

import (
	"container/heap"
	"time"
)

// A PriorityQueue implements heap.Interface and holds Items.
type PriorityQueue []*Item

// Len returns length of priorityQueue
func (pq PriorityQueue) Len() int { return len(pq) }

// Less is the function used for priority queue order
func (pq PriorityQueue) Less(i, j int) bool {
	// We want Pop to give us the lowest duration
	return pq[i].TaskDuration.Nanoseconds() < pq[j].TaskDuration.Nanoseconds()
}

// Swap swaps 2 elements
func (pq PriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].Index = i
	pq[j].Index = j
}

// Push adds item in queue
func (pq *PriorityQueue) Push(x any) {
	n := len(*pq)
	item := x.(*Item)
	item.Index = n
	*pq = append(*pq, item)
}

// Pop returns first item in queue and removes it
func (pq *PriorityQueue) Pop() any {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil  // avoid memory leak
	item.Index = -1 // for safety
	*pq = old[0 : n-1]
	return item
}

// Duration converts float64 into duration
func Duration(f float64) time.Duration {
	return time.Duration(f * 1e9)
}

// Update modifies the priority and value of an Item in the queue.
func (pq *PriorityQueue) Update(item *Item, Name string, duration, initialDuration time.Duration) {
	item.Name = Name
	item.TaskDuration = duration
	item.InitialTaskDuration = initialDuration
	heap.Fix(pq, item.Index)
}
