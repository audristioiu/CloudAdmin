package schedulers

import (
	"cloudadmin/helpers"
	"cloudadmin/priority_queue"
	"container/heap"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	listersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"
)

const hybridSchedulerName = "round-robin-sjf-scheduler"

// HybridScheduler represents info about HybridScheduler
type HybridScheduler struct {
	clientset  *kubernetes.Clientset
	podQueue   chan *v1.Pod
	nodeLister listersv1.NodeLister
}

// NewHybridScheduler returns a HybridScheduler
func NewHybridScheduler(podQueue chan *v1.Pod, quit chan struct{}) HybridScheduler {
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Fatal(err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatal(err)
	}

	return HybridScheduler{
		clientset:  clientset,
		podQueue:   podQueue,
		nodeLister: initInformers(clientset, podQueue, quit),
	}
}

// Run reads json file with tasks duration from pod, creates priority queue and map of tasks(pod name mapped to pod details)
// and uses nodes to run scheduler
func (s *HybridScheduler) Run() {
	var taskItems []priority_queue.TaskItem
	tasksDurationBytes, err := os.ReadFile("data/tasks_duration.json")
	if err != nil {
		log.Fatalf("cannot open file %v", err.Error())
		return
	}
	err = json.Unmarshal(tasksDurationBytes, &taskItems)
	if err != nil {
		log.Fatalf("cannot unmarshal into taskItem %v", err.Error())
		return
	}

	priorityQueue := helpers.CreatePQ(taskItems)

	mapPodsTasks := make(map[string]*v1.Pod, len(taskItems))
	count := 0
	for schedPod := range s.podQueue {
		mapPodsTasks[schedPod.Name] = schedPod
		count++
		if count == len(taskItems) {
			break
		}
	}
	nodes, err := s.nodeLister.List(labels.Everything())
	if err != nil {
		return
	}
	s.RoundRobinShortestJobFirstAlgorithm(nodes, mapPodsTasks, priorityQueue)
}

// ScheduleOne tries to binds found pod from algorithm to node .
func (s *HybridScheduler) ScheduleOne(p *v1.Pod, priorities map[string]int, value int) {

	node := s.findBestNode(priorities, value)
	err := s.bindPod(p, node)
	if err != nil {
		log.Println("failed to bind pod", err.Error())
		return
	}

	message := fmt.Sprintf("Placed pod [%s/%s] on %s\n", p.Namespace, p.Name, node)

	err = s.emitEvent(p, message)
	if err != nil {
		log.Println("failed to emit scheduled event", err.Error())
		return
	}

	fmt.Println(message)
}

func (s *HybridScheduler) bindPod(p *v1.Pod, node string) error {
	return s.clientset.CoreV1().Pods(p.Namespace).Bind(context.Background(), &v1.Binding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      p.Name,
			Namespace: p.Namespace,
		},
		Target: v1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Node",
			Name:       node,
		},
	}, metav1.CreateOptions{})
}

func (s *HybridScheduler) emitEvent(p *v1.Pod, message string) error {
	timestamp := time.Now().UTC()
	_, err := s.clientset.CoreV1().Events(p.Namespace).Create(context.Background(), &v1.Event{
		Count:          1,
		Message:        message,
		Reason:         "HybridScheduled",
		LastTimestamp:  metav1.NewTime(timestamp),
		FirstTimestamp: metav1.NewTime(timestamp),
		Type:           "Normal",
		Source: v1.EventSource{
			Component: hybridSchedulerName,
		},
		InvolvedObject: v1.ObjectReference{
			Kind:      "Pod",
			Name:      p.Name,
			Namespace: p.Namespace,
			UID:       p.UID,
		},
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: p.Name + "-",
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func (s *HybridScheduler) prioritize(nodes []*v1.Node) map[string]int {
	priorities := make(map[string]int)
	count := 1
	for _, node := range nodes {
		priorities[node.Name] = count
		count++
	}
	log.Println("calculated priorities:", priorities)
	return priorities
}

func (s *HybridScheduler) findBestNode(priorities map[string]int, value int) string {
	var bestNode string
	for node, p := range priorities {
		if p == value {
			bestNode = node
			break
		}
	}
	return bestNode
}

// RoundRobinShortestJobFirstAlgorithm uses a constant min(minimum burst time) and decreases every execution with this value.
// Tasks with duration equal to 0 or below are added to a slice of string which will be the order of application
func (s *HybridScheduler) RoundRobinShortestJobFirstAlgorithm(nodes []*v1.Node, mapPodsTaks map[string]*v1.Pod, pq priority_queue.PriorityQueue) {

	priorities := s.prioritize(nodes)
	countNodes := 1
	nrOfTasks := pq.Len()
	firstElem := heap.Pop(&pq).(*priority_queue.Item)
	for firstElem != nil {
		count := 0
		lenPQ := pq.Len() - 1
		for count != lenPQ && lenPQ != -1 {
			item := heap.Pop(&pq).(*priority_queue.Item)
			durationDiff := float64(item.TaskDuration.Seconds()) - float64(firstElem.TaskDuration.Seconds())
			if durationDiff <= float64(0) {
				for kPod, vPod := range mapPodsTaks {
					if strings.Contains(kPod, item.Name) {
						s.ScheduleOne(vPod, priorities, countNodes)
						countNodes++
						if countNodes == nrOfTasks {
							countNodes = 1
						}
					}
				}
			} else {
				newItem := &priority_queue.Item{
					Name:         item.Name,
					TaskDuration: priority_queue.Duration(float64(durationDiff)),
				}
				heap.Push(&pq, newItem)
				pq.Update(newItem, newItem.Name, newItem.TaskDuration)
			}
			count++
		}
		if pq.Len() > 0 {
			firstElem = heap.Pop(&pq).(*priority_queue.Item)
		} else {
			firstElem = nil
		}

	}
	log.Println("HYBRYD ROUND ROBIN SHORTEST JOB FIRST ALGORITHM SUCCESFULLY SCHEDULED ALL Tasks")
}
