#!/bin/bash
echo $1
kubectl delete deployment main-go-deployment --namespace $1
kubectl delete deployment random-scheduler-go-deployment
kubectl delete deployment rr-sjf-scheduler-go-deployment
kubectl delete serviceaccount random-scheduler-go-deployment
kubectl delete serviceaccount rr-sjf-scheduler-go-deployment
kubectl delete namespace $1