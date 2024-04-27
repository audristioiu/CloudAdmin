package schedulers

import (
	"context"
	"fmt"
	"log"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	listersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"
)

const hybridSchedulerName = "rr-sjf-scheduler-go-deployment"

// HybridRoundRobinSJFScheduler represents info about HybridRoundRobinSJFScheduler
type HybridRoundRobinSJFScheduler struct {
	clientset  *kubernetes.Clientset
	podQueue   chan *v1.Pod
	nodeLister listersv1.NodeLister
	counter    int
}

// NewHybridRoundRobinSJFScheduler returns a HybridRoundRobinSJFScheduler
func NewHybridRoundRobinSJFScheduler(podQueue chan *v1.Pod, quit chan struct{}) HybridRoundRobinSJFScheduler {
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Fatal(err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatal(err)
	}

	return HybridRoundRobinSJFScheduler{
		clientset:  clientset,
		podQueue:   podQueue,
		counter:    0,
		nodeLister: initInformers(clientset, podQueue, quit),
	}

}

// Run starts schedulling
func (s *HybridRoundRobinSJFScheduler) Run(quit chan struct{}) {
	wait.Until(s.ScheduleOne, 0, quit)
}

// ScheduleOne tries to binds found pod from algorithm to node .
func (s *HybridRoundRobinSJFScheduler) ScheduleOne() {
	p := <-s.podQueue
	fmt.Println("found a pod to schedule:", p.Namespace, "/", p.Name)
	nodes, err := s.nodeLister.List(labels.Everything())
	if err != nil {
		log.Println("failed to list nodes", err.Error())
		return
	}
	priorities := s.prioritize(nodes)
	node := s.findBestNode(priorities, s.counter)
	err = s.bindPod(p, node)
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

	s.counter++
	if s.counter >= len(nodes) {
		s.counter = 0
	}

}

func (s *HybridRoundRobinSJFScheduler) bindPod(p *v1.Pod, node string) error {
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

func (s *HybridRoundRobinSJFScheduler) emitEvent(p *v1.Pod, message string) error {
	timestamp := time.Now().UTC()
	_, err := s.clientset.CoreV1().Events(p.Namespace).Create(context.Background(), &v1.Event{
		Count:          1,
		Message:        message,
		Reason:         "HybridRRSJFScheduled",
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
		log.Println("failed to create event", err.Error())
		return err
	}
	return nil
}

func (s *HybridRoundRobinSJFScheduler) prioritize(nodes []*v1.Node) map[string]int {
	priorities := make(map[string]int)
	count := 0
	for _, node := range nodes {
		priorities[node.Name] = count
		count++
	}
	log.Println("calculated priorities:", priorities)
	return priorities
}

func (s *HybridRoundRobinSJFScheduler) findBestNode(priorities map[string]int, value int) string {
	var bestNode string
	for node, p := range priorities {
		if p == value {
			bestNode = node
			break
		}
	}
	return bestNode
}
