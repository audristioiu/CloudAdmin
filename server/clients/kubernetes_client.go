package clients

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	client "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// KubernetesClient represents info about Kubernetes client
type KubernetesClient struct {
	ctx        context.Context
	kubeClient *client.Clientset
	kubeLogger *zap.Logger
}

// NewKubernetesClient returns a KubernetesCllient
func NewKubernetesClient(ctx context.Context, logger *zap.Logger, kubeConfig string) *KubernetesClient {
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeConfig)
	if err != nil {
		logger.Error("failed to build config from flags", zap.Error(err))
		return nil
	}

	clientset, err := client.NewForConfig(cfg)
	if err != nil {
		logger.Error("failed to init kube client", zap.Error(err))
		return nil
	}
	return &KubernetesClient{
		ctx:        ctx,
		kubeLogger: logger,
		kubeClient: clientset,
	}
}

// CreateNamespace creates new namespace for user
func (k *KubernetesClient) CreateNamespace(userName string) (string, error) {
	namespaceClient := k.kubeClient.CoreV1().Namespaces()
	newNamespace := &apiv1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace-" + userName,
		},
	}
	resNameSpace, err := namespaceClient.Create(k.ctx, newNamespace, metav1.CreateOptions{})
	if err != nil {
		k.kubeLogger.Error("failed to create new namespace for user", zap.String("user_name", userName), zap.Error(err))
		if !strings.Contains(err.Error(), "already exists") {
			return "", err
		}
	}
	k.kubeLogger.Info("Created new namespace", zap.String("namespace", resNameSpace.GetName()))
	return resNameSpace.GetName(), nil
}

// DeleteNamespace deletes namespace for user
func (k *KubernetesClient) DeleteNamespace(username string) error {
	namespaceClient := k.kubeClient.CoreV1().Namespaces()
	deletePolicy := metav1.DeletePropagationForeground
	err := namespaceClient.Delete(k.ctx, "namespace-"+username, metav1.DeleteOptions{
		PropagationPolicy: &deletePolicy,
	})
	if err != nil {
		k.kubeLogger.Error("failed to delete namespace", zap.String("user", username), zap.Error(err))
		return err
	}
	k.kubeLogger.Info("Deleted namespace", zap.String("user", username))
	return nil
}

// CreateDeployment creates a deployment for image in the required namespace with a specific nr of replicas
func (k *KubernetesClient) CreateDeployment(tagName, imageName, namespace string, nrReplicas int32) error {
	deploymentsClient := k.kubeClient.AppsV1().Deployments(namespace)
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: imageName + "-deployment",
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &nrReplicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": imageName,
				},
			},
			Template: apiv1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": imageName,
					},
				},
				Spec: apiv1.PodSpec{
					Containers: []apiv1.Container{
						{
							Name:  imageName,
							Image: tagName,
						},
					},
				},
			},
		},
	}

	result, err := deploymentsClient.Create(k.ctx, deployment, metav1.CreateOptions{})
	if err != nil {
		k.kubeLogger.Error("failed to create deployment", zap.Error(err))
		return err
	}
	k.kubeLogger.Info("Created deployment", zap.String("deployment_name", result.GetName()))
	return nil
}

// DeleteDeployment deletes deployment from the required namespace
func (k *KubernetesClient) DeleteDeployment(deployName, namespace string) error {
	deploymentsClient := k.kubeClient.AppsV1().Deployments(namespace)
	deletePolicy := metav1.DeletePropagationForeground
	err := deploymentsClient.Delete(k.ctx, deployName, metav1.DeleteOptions{
		PropagationPolicy: &deletePolicy,
	})
	if err != nil {
		k.kubeLogger.Error("failed to delete deployment", zap.String("deploy_name", deployName), zap.Error(err))
		return err
	}
	k.kubeLogger.Info("Deleted deployment", zap.String("deployment_name", deployName))
	return nil
}

// CreatePod creates pod using podName
func (k *KubernetesClient) CreatePod(podName, tagName, namespace string) error {
	appName := strings.Split(podName, "-")[0]
	podClient := k.kubeClient.CoreV1().Pods(namespace)
	pod := apiv1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: namespace,
			Labels: map[string]string{
				"app": appName,
			},
		},
		Spec: apiv1.PodSpec{
			Containers: []apiv1.Container{
				{
					Name:            appName,
					Image:           tagName,
					ImagePullPolicy: apiv1.PullIfNotPresent,
				},
			},
		},
	}
	respPod, err := podClient.Create(k.ctx, &pod, metav1.CreateOptions{})
	if err != nil {
		k.kubeLogger.Error("failed to create pod", zap.Error(err))
		return err
	}
	k.kubeLogger.Info("created pod", zap.String("pod_name", respPod.GetName()))
	return nil
}

// DeletePod deletes pod from the required namesapce
func (k *KubernetesClient) DeletePod(podName, namespace string) error {
	deploymentsClient := k.kubeClient.CoreV1().Pods(namespace)
	deletePolicy := metav1.DeletePropagationForeground
	err := deploymentsClient.Delete(k.ctx, podName, metav1.DeleteOptions{
		PropagationPolicy: &deletePolicy,
	})
	if err != nil {
		k.kubeLogger.Error("failed to delete deployment", zap.String("pod_name", podName), zap.Error(err))
		return err
	}
	k.kubeLogger.Info("Deleted pod", zap.String("pod_name", podName))
	return nil
}

// GetLogsForPodName iterates through replicas of podName and returns logs
func (k *KubernetesClient) GetLogsForPodName(podName, namespace string) (string, error) {
	logList := make([]string, 0)
	podsClient := k.kubeClient.CoreV1().Pods(namespace)
	pods, err := podsClient.List(k.ctx, metav1.ListOptions{LabelSelector: "app=" + podName})
	if err != nil {
		k.kubeLogger.Error("failed to list pods", zap.Error(err))
		return "", err
	}
	for _, pod := range pods.Items {
		logFromPod := podsClient.GetLogs(pod.Name, &apiv1.PodLogOptions{})
		podLogs, err := logFromPod.Stream(k.ctx)
		if err != nil {
			k.kubeLogger.Error("failed to get stream", zap.Error(err))
			return "", err
		}
		defer podLogs.Close()

		buf := new(bytes.Buffer)
		_, err = io.Copy(buf, podLogs)
		if err != nil {
			k.kubeLogger.Error("error in copy information from podLogs to buf", zap.Error(err))
			return "", err
		}
		str := buf.String()
		logList = append(logList, str)
	}
	if len(logList) == 0 {
		return "", fmt.Errorf("failed to get logs")
	}

	return logList[0], nil
}
