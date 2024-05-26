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
	metricsclientset "k8s.io/metrics/pkg/client/clientset/versioned"
)

const MinMinSchedulerName = "user-priority-min-min-scheduler-go-deployment"

// UserPriorityMinMinScheduler represents a scheduler that implements the User Priority Guided Min-Min Algorithm
type UserPriorityMinMinScheduler struct {
	clientset     *kubernetes.Clientset
	podQueue      chan *v1.Pod
	counter       int
	nodeLister    listersv1.NodeLister
	metricsClient *metricsclientset.Clientset
}

func NewUserPriorityMinMinScheduler(podQueue chan *v1.Pod, quit chan struct{}) UserPriorityMinMinScheduler {
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Fatal(err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatal(err)
	}

	metricsClient, err := metricsclientset.NewForConfig(config)
	if err != nil {
		log.Fatal("Failed to create metrics client:", err)
	}

	log.Println("created min min scheduler")

	return UserPriorityMinMinScheduler{
		clientset:     clientset,
		metricsClient: metricsClient,
		podQueue:      podQueue,
		nodeLister:    initInformers(clientset, podQueue, quit),
	}
}

func (s *UserPriorityMinMinScheduler) Run(quit chan struct{}) {
	log.Println("started running")
	wait.Until(s.ScheduleOne, 0, quit)
}

func (s *UserPriorityMinMinScheduler) ScheduleOne() {
	log.Println("entering scheduleone")
	p := <-s.podQueue
	fmt.Println("found a pod to schedule:", p.Namespace, "/", p.Name)
	log.Println("found a pod to schedule:", p.Namespace, "/", p.Name)

	nodes, err := s.nodeLister.List(labels.Everything())
	log.Println("listed all nodes")
	if err != nil {
		log.Println("failed to list nodes", err.Error())
		return
	}

	bestNode := s.findBestFit(p, nodes)
	log.Println("found best node")
	if bestNode == "" {
		log.Println("cannot find node that fits pod")
		return
	}

	err = s.bindPod(p, bestNode)
	if err != nil {
		log.Println("failed to bind pod", err.Error())
		return
	}

	message := fmt.Sprintf("Placed pod [%s/%s] on %s\n", p.Namespace, p.Name, bestNode)
	fmt.Println(message)

	err = s.emitEvent(p, message)
	if err != nil {
		log.Println("failed to emit scheduled event", err.Error())
		return
	}
}

func (s *UserPriorityMinMinScheduler) findBestFit(pod *v1.Pod, nodes []*v1.Node) string {
	minCompletionTime := float64(9999999999)
	var bestNode string

	for _, node := range nodes {
		estimatedTime := s.calculateCompletionTime(node, pod)
		if estimatedTime < minCompletionTime {
			minCompletionTime = estimatedTime
			bestNode = node.Name
		}
	}

	return bestNode
}

func (s *UserPriorityMinMinScheduler) calculateCompletionTime(node *v1.Node, pod *v1.Pod) float64 {
	nodeMetrics, err := s.metricsClient.MetricsV1beta1().NodeMetricses().Get(context.Background(), node.Name, metav1.GetOptions{})
	if err != nil {
		log.Printf("error getting node metrics: %v", err)
		return float64(0)
	}

	cpuUsage := nodeMetrics.Usage.Cpu().MilliValue()
	cpuCapacity := node.Status.Capacity.Cpu().MilliValue()

	cpuUtilization := float64(cpuUsage) / float64(cpuCapacity)

	log.Println("node cpu:", cpuUtilization)

	return cpuUtilization * 100.0
}

func (s *UserPriorityMinMinScheduler) bindPod(p *v1.Pod, node string) error {
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

func (s *UserPriorityMinMinScheduler) emitEvent(p *v1.Pod, message string) error {
	timestamp := time.Now().UTC()
	_, err := s.clientset.CoreV1().Events(p.Namespace).Create(context.Background(), &v1.Event{
		Count:          1,
		Message:        message,
		Reason:         "UserPriorityMinScheduled",
		LastTimestamp:  metav1.NewTime(timestamp),
		FirstTimestamp: metav1.NewTime(timestamp),
		Type:           "Normal",
		Source: v1.EventSource{
			Component: MinMinSchedulerName,
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
