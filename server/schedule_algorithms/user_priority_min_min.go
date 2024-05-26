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

// func calculateAvailableEfficiency(namespace string, resource domain.Resource, metrics map[string]map[string][]domain.PodContainerMetrics) float64 {
// 	// Implement logic to adjust resource efficiency based on current usage
// 	// Example: reduce efficiency based on CPU and memory usage percentage
// 	return resource.Efficiency * (1 - metrics[namespace][resource.Name][0].CPUMemoryMetrics[0]/100)
// }

// UserPriorityMinMinAlgorithm schedules tasks based on the Min-Min scheduling principle but prioritizes VIP users first
func UserPriorityMinMinAlgorithm(pq priority_queue_min_min.PriorityQueue, pairNames [][]string, logger *zap.Logger) [][]string {
	// var scheduledTasks [][]string
	// podMetrics, err := client.ListPodsMetrics()
	// if err != nil {

	// 	logger.Error("Failed to retrieve pod metrics", zap.Error(err))
	// 	return nil
	// }

	// resources := helpers.AdjustResourcesBasedOnUsage(helpers.GetAllResources(), podMetrics)
	// for pq.Len() > 0 {
	// 	task := heap.Pop(&pq).(*domain.TaskMinMin)
	// 	minCompletionTime := float64(99999999)
	// 	selectedResource := ""

	// 	for _, resource := range resources {
	// 		availableEfficiency := calculateAvailableEfficiency(namespace, resource, podMetrics)
	// 		estimatedTime := float64(task.Duration) / float64(time.Second) / availableEfficiency
	// 		if estimatedTime < minCompletionTime {
	// 			minCompletionTime = estimatedTime
	// 			selectedResource = resource.Name
	// 		}
	// 	}

	// 	scheduledTasks = append(scheduledTasks, []string{task.Name, selectedResource})
	// }
	// return scheduledTasks

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
