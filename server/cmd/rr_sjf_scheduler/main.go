package main

import (
	"cloudadmin/schedulers"
	"math/rand"
	"time"

	v1 "k8s.io/api/core/v1"
)

func main() {

	rand.NewSource(time.Now().Unix())

	podQueue := make(chan *v1.Pod, 300)
	defer close(podQueue)

	quit := make(chan struct{})
	defer close(quit)

	scheduler := schedulers.NewHybridScheduler(podQueue, quit)
	scheduler.Run()
}
