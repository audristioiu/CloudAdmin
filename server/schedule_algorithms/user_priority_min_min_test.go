package schedule_alghoritms

import (
	"bytes"
	"cloudadmin/domain"
	"cloudadmin/helpers"
	"container/heap"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest"
)

func TestCreateMinMinPQ(t *testing.T) {
	appNames := []string{"app1.c", "app2.c", "app3.c", "app4.c"}
	appPrioritiesMap := map[string]int{
		"app1.c": 2,
		"app2.c": 3,
		"app3.c": 1,
		"app4.c": 0,
	}

	pQueue := helpers.CreateMinMinPQ(appPrioritiesMap, appNames)
	if pQueue.Len() != 4 {
		t.Errorf("Expected priority queue length of 4, got %d", pQueue.Len())
	}

	// Assuming higher priority number means higher priority, check if highest priority item is app2.c
	highestPriorityItem := heap.Pop(&pQueue).(*domain.MinMinItem)
	if highestPriorityItem.Name != "app2.c" {
		t.Errorf("Expected highest priority item to be 'app2.c', got '%s'", highestPriorityItem.Name)
	}

	// Optionally, check the ordering of the entire priority queue
	expectedOrder := []string{"app2.c", "app1.c", "app3.c", "app4.c"}
	for i := 1; pQueue.Len() > 0; i++ {
		item := heap.Pop(&pQueue).(*domain.MinMinItem)
		if item.Name != expectedOrder[i] {
			t.Errorf("At index %d, expected %s, got %s", i, expectedOrder[i], item.Name)
		}
	}
}

func TestUserPriorityAlgorithm(t *testing.T) {
	appNames := []string{"app1.c", "app2.c", "app3.c", "app4.c"}
	appPrioritiesMap := map[string]int{
		"app1.c": 2,
		"app2.c": 3,
		"app3.c": 1,
		"app4.c": 0,
	}
	pQueue := helpers.CreateMinMinPQ(appPrioritiesMap, appNames)
	pairNames := [][]string{
		{"app3-c", "app3-c"},
		{"app4-c", "app4-c"},
		{"app2-c", "app2-c"},
		{"app1-c", "app1-c"},
	}

	var buf bytes.Buffer
	logger := zaptest.NewLogger(t, zaptest.WrapOptions(zap.Hooks(func(entry zapcore.Entry) error {
		buf.WriteString(entry.Message)
		buf.WriteByte('\n')
		return nil
	})))
	pairs := UserPriorityMinMinAlgorithm(pQueue, pairNames, logger)
	if len(pairs) != 4 || pairs[0][1] != "app2-c" || pairs[1][1] != "app1-c" || pairs[2][1] != "app3-c" || pairs[3][1] != "app4-c" {
		t.Fatalf("failed to run user priority algorithm on : %v . Result %v", appNames, pairs)
	}
}
