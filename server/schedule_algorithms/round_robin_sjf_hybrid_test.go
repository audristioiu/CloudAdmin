package schedule_alghoritms

import (
	"bytes"
	"cloudadmin/domain"
	"cloudadmin/helpers"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest"
)

func TestCreatePQ(t *testing.T) {
	items := []domain.TaskItem{
		{
			Name:     "app1.c",
			Duration: "20.5s",
		},
		{
			Name:     "app2.c",
			Duration: "15.7s",
		},
		{
			Name:     "app3.c",
			Duration: "100.0s",
		},
		{
			Name:     "app4.c",
			Duration: "86.5s",
		},
	}
	pQueue := helpers.CreatePQ(items)
	if pQueue.Len() != 4 {
		t.Fatalf("failed to create pq for items : %v", items)
	}
}

func TestRRSJFAlgorithm(t *testing.T) {
	items := []domain.TaskItem{
		{
			Name:     "app2.c",
			Duration: "15.7s",
		},
		{
			Name:     "app1.c",
			Duration: "20.5s",
		},
		{
			Name:     "app4.c",
			Duration: "86.5s",
		},
		{
			Name:     "app3.c",
			Duration: "100.0s",
		},
	}
	pQueue := helpers.CreatePQ(items)
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
	pairs := RoundRobinShortestJobFirstAlgorithm(pQueue, pairNames, logger)
	if len(pairs) != 4 || pairs[0][1] != "app2-c" || pairs[1][1] != "app1-c" || pairs[2][1] != "app4-c" || pairs[3][1] != "app3-c" {
		t.Fatalf("failed to run rr sjf algorithm on : %v . Result %v", items, pairs)
	}
}
