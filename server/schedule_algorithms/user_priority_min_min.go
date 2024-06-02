package schedule_alghoritms

import (
	"cloudadmin/domain"
	"cloudadmin/helpers"
	"cloudadmin/priority_queue_min_min"
	"container/heap"
	"strings"

	"go.uber.org/zap"
)

// CreatePriorityQueueBasedOnTasksDuration reads tasks duration file and creates a priority queue used for the User Priority Guided Min-Min Scheduling Algorithm
func CreatePriorityQueueBasedOnPriority(appPrioritiesMap map[string]int, appNames []string, logger *zap.Logger) (priority_queue_min_min.PriorityQueue, error) {
	priorityQueue := helpers.CreateMinMinPQ(appPrioritiesMap, appNames)
	return priorityQueue, nil
}

// UserPriorityMinMinAlgorithm schedules tasks based on the Min-Min scheduling principle but prioritizes VIP users first
func UserPriorityMinMinAlgorithm(pq priority_queue_min_min.PriorityQueue, pairNames [][]string, logger *zap.Logger) [][]string {

	newPairNames := make([][]string, 0)
	for pq.Len() > 0 {
		item := heap.Pop(&pq).(*domain.MinMinItem)
		// Process the item directly, no need to push it back unless some condition is met
		for _, pair := range pairNames {
			searchName := strings.ReplaceAll(strings.ReplaceAll(item.Name, ".", "-"), "_", "-")
			if pair[1] == searchName {
				newPairNames = append(newPairNames, pair)
			}
		}
	}
	logger.Info("USER PRIORITY MIN MIN ALGORITHM SCHEDULED")
	return newPairNames
}
