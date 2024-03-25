package schedule_alghoritms

import (
	"cloudadmin/helpers"
	"cloudadmin/priority_queue"
	"container/heap"
	"encoding/json"
	"os"
	"strconv"
	"strings"

	"go.uber.org/zap"
)

// CreatePriorityQueueBasedOnTasksDuration reads tasks duration file and creates a priority queue used for Round Robin Shortest Job First Algorithm
func CreatePriorityQueueBasedOnTasksDuration(fileName string, logger *zap.Logger) (priority_queue.PriorityQueue, error) {
	var taskItems []priority_queue.TaskItem
	tasksDurationBytes, err := os.ReadFile(fileName)
	if err != nil {
		logger.Error("cannot open file ", zap.Error(err))
		return nil, err
	}
	err = json.Unmarshal(tasksDurationBytes, &taskItems)
	if err != nil {
		logger.Error("failed to unmarshal task duration items", zap.Error(err))
		return nil, err
	}

	priorityQueue := helpers.CreatePQ(taskItems)
	return priorityQueue, nil
}

// RoundRobinShortestJobFirstAlgorithm uses a constant min(minimum burst time) and decreases every execution with this value.
// Tasks with duration equal to 0 or below are added to a slice of string which will be the order of applications
func RoundRobinShortestJobFirstAlgorithm(pq priority_queue.PriorityQueue, pairNames [][]string, logger *zap.Logger) [][]string {

	newPairNames := make([][]string, 0)
	firstElem := heap.Pop(&pq).(*priority_queue.Item)
	for firstElem != nil {
		newItem := &priority_queue.Item{
			Name:                firstElem.Name,
			InitialTaskDuration: firstElem.InitialTaskDuration,
			TaskDuration:        firstElem.TaskDuration,
		}
		heap.Push(&pq, newItem)
		pq.Update(newItem, newItem.Name, newItem.TaskDuration, newItem.InitialTaskDuration)
		count := 0
		lenPQ := pq.Len()
		for count != lenPQ && lenPQ != -1 {
			item := heap.Pop(&pq).(*priority_queue.Item)
			durationDiff := float64(item.TaskDuration.Seconds()) - float64(firstElem.TaskDuration.Seconds())
			if durationDiff <= float64(0) {
				for _, pair := range pairNames {
					if pair[1] == strings.ReplaceAll(item.Name, ".", "-") {
						auxPair := pair
						floatDuration := strconv.FormatFloat(item.InitialTaskDuration.Seconds(), 'f', 3, 64)
						auxPair = append(auxPair, floatDuration)
						newPairNames = append(newPairNames, auxPair)
					}
				}
			} else {
				newItem := &priority_queue.Item{
					Name:                item.Name,
					InitialTaskDuration: item.InitialTaskDuration,
					TaskDuration:        priority_queue.Duration(float64(durationDiff)),
				}
				heap.Push(&pq, newItem)
				pq.Update(newItem, newItem.Name, newItem.TaskDuration, newItem.InitialTaskDuration)
			}
			count++
		}
		if pq.Len() > 0 {
			firstElem = heap.Pop(&pq).(*priority_queue.Item)
		} else {
			firstElem = nil
		}

	}
	logger.Info("HYBRYD ROUND ROBIN SHORTEST JOB FIRST ALGORITHM SUCCESFULLY SCHEDULED ALL Tasks")
	return newPairNames
}
