package priority_queue

import "time"

// TaskItem represents info for hybrid algorithm between Round Robin and Shortest Job First
type TaskItem struct {
	Name     string `json:"name"`
	Duration string `json:"duration"`
}

// Item is something we manage in a priority queue.
type Item struct {
	Name                string
	InitialTaskDuration time.Duration
	TaskDuration        time.Duration
	Index               int
}
