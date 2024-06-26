package clients

import (
	"bytes"
	"cloudadmin/domain"
	"cloudadmin/helpers"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"go.uber.org/zap"

	appsv1 "k8s.io/api/apps/v1"
	hpav2 "k8s.io/api/autoscaling/v2"
	apiv1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	client "k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
	metricsKube "k8s.io/metrics/pkg/client/clientset/versioned"
	"k8s.io/utils/ptr"
)

// KubernetesClient represents info about Kubernetes client
type KubernetesClient struct {
	ctx                 context.Context
	kubeClient          *client.Clientset
	metricsKubeClient   *metricsKube.Clientset
	kubeLogger          *zap.Logger
	schedulerRegisterID string
}

// NewKubernetesClient returns a KubernetesCllient
func NewKubernetesClient(ctx context.Context, logger *zap.Logger, kubeConfig, schedulerID string) *KubernetesClient {
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeConfig)
	if err != nil {
		logger.Error("failed to build config from flags", zap.Error(err))
		return nil
	}
	cfg.QPS = 100
	cfg.Burst = 100

	clientset, err := client.NewForConfig(cfg)
	if err != nil {
		logger.Error("failed to init kube client", zap.Error(err))
		return nil
	}
	metrics, err := metricsKube.NewForConfig(cfg)
	if err != nil {
		logger.Error("failed to init kube metrics client", zap.Error(err))
		return nil
	}
	return &KubernetesClient{
		ctx:                 ctx,
		kubeLogger:          logger,
		kubeClient:          clientset,
		metricsKubeClient:   metrics,
		schedulerRegisterID: schedulerID,
	}
}

// ListPodsMetrics gets pods metrics
func (k *KubernetesClient) ListPodsMetrics() (map[string]map[string][]domain.PodContainerMetrics, error) {
	podMetricsMap := make(map[string]map[string][]domain.PodContainerMetrics, 0)
	cpuUsageTotal := int64(0)
	memUsageTotal := int64(0)
	namespaces := k.ListNamespaces()
	for _, namespace := range namespaces {
		if strings.Contains(namespace, "namespace-") || namespace == "default" {
			containerMetricsMap := make(map[string][]domain.PodContainerMetrics, 0)
			podsFromNamespace := k.ListPods(namespace)
			for _, podName := range podsFromNamespace {
				podMetrics, err := k.metricsKubeClient.MetricsV1beta1().PodMetricses(namespace).Get(k.ctx, podName, metav1.GetOptions{})
				if err != nil {
					k.kubeLogger.Error("failed to list metrics for pods", zap.Error(err))
					continue
				}
				for _, podContainer := range podMetrics.Containers {
					cpuUsageTotal += podContainer.Usage.Cpu().MilliValue()
					memUsageTotal += podContainer.Usage.Memory().Value()
				}
			}
			for _, podName := range podsFromNamespace {
				podMetrics, err := k.metricsKubeClient.MetricsV1beta1().PodMetricses(namespace).Get(k.ctx, podName, metav1.GetOptions{})
				if err != nil {
					k.kubeLogger.Error("failed to list metrics for pods", zap.Error(err))
					continue
				}
				podCPUMemoryMetrics := make([]domain.PodContainerMetrics, 0)
				for _, podContainer := range podMetrics.Containers {
					cpuPercentage := float64(podContainer.Usage.Cpu().MilliValue()) / float64(cpuUsageTotal) * 100
					memoryPercentage := float64(podContainer.Usage.Memory().Value()) / float64(memUsageTotal) * 100
					podCPUMemoryMetrics = append(podCPUMemoryMetrics, domain.PodContainerMetrics{

						CPUMemoryMetrics: []float64{
							cpuPercentage,
							memoryPercentage,
							float64(podContainer.Usage.Cpu().MilliValue()),
							float64(podContainer.Usage.Memory().Value() / 1e6),
						},
						PodContainerName: podContainer.Name,
					})
				}
				containerMetricsMap[podName] = podCPUMemoryMetrics
			}
			podMetricsMap[namespace] = containerMetricsMap
		}

	}
	return podMetricsMap, nil
}

// ListNodesMetrics gets node metrics
func (k *KubernetesClient) ListNodesMetrics() (map[string][]float64, error) {
	nodeMetricsMap := make(map[string][]float64, 0)
	nodes := k.ListNodes()
	for _, node := range nodes {
		nodeMetrics, err := k.metricsKubeClient.MetricsV1beta1().NodeMetricses().Get(k.ctx, node.Name, metav1.GetOptions{})
		if err != nil {
			k.kubeLogger.Error("failed to get metrics for node", zap.String("node", node.Name), zap.Error(err))
		}
		nodeCPU := float64(nodeMetrics.Usage.Cpu().MilliValue()) / float64(node.Status.Capacity.Cpu().MilliValue())
		nodeMemory := float64(nodeMetrics.Usage.Memory().Value()) / float64(node.Status.Capacity.Memory().Value())
		nodeMetricsMap[nodeMetrics.Name] = []float64{
			nodeCPU,
			nodeMemory,
			float64(nodeMetrics.Usage.Cpu().MilliValue()),
			float64(nodeMetrics.Usage.Memory().Value()) / 1e6,
		}
	}
	return nodeMetricsMap, nil
}

// GetNodeCPUMetric retrieves node cpu metric as percentage for a node
func (k *KubernetesClient) GetNodeCPUMetric(nodeName string, totalCPU int64) (float64, error) {
	nodeMetrics, err := k.metricsKubeClient.MetricsV1beta1().NodeMetricses().Get(k.ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		k.kubeLogger.Error("failed to get metrics for node", zap.Error(err))
		return 0, err
	}

	cpuPercentage := float64(nodeMetrics.Usage.Cpu().MilliValue()) / float64(totalCPU) * 100

	return cpuPercentage, nil
}

// GetNodeMemoryMetric retrieves node memory metric as percentage for a node
func (k *KubernetesClient) GetNodeMemoryMetric(nodeName string, totalMemory int64) (float64, error) {
	nodeMetrics, err := k.metricsKubeClient.MetricsV1beta1().NodeMetricses().Get(k.ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return 0, err
	}

	memPercentage := float64(nodeMetrics.Usage.Memory().Value()) / float64(totalMemory) * 100

	return memPercentage, nil
}

// ListNodes lists nodes from kubernetes
func (k *KubernetesClient) ListNodes() []apiv1.Node {
	nsList, err := k.kubeClient.CoreV1().Nodes().List(k.ctx, metav1.ListOptions{})
	if err != nil {
		k.kubeLogger.Error("failed to list nodes", zap.Error(err))
		return nil
	}
	return nsList.Items
}

// CreateNamespace creates new namespace for user
func (k *KubernetesClient) CreateNamespace(userName, scheduleType string) (string, error) {

	var nameSpaceName string

	nr := strconv.Itoa(helpers.GetRandomInt())
	namespaces := k.ListNamespaces()
	userNameSpace := helpers.CheckSliceContains(namespaces, userName)
	if userNameSpace == "" {
		namespaceClient := k.kubeClient.CoreV1().Namespaces()
		newNamespace := &apiv1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: userName + nr,
			},
		}
		resNameSpace, err := namespaceClient.Create(k.ctx, newNamespace, metav1.CreateOptions{})
		if err != nil {
			k.kubeLogger.Error("failed to create new namespace for user", zap.String("user_name", userName), zap.Error(err))
			return "", err
		}
		nameSpaceName = resNameSpace.GetName()
	} else {
		nameSpaceName = userNameSpace
	}
	if scheduleType != "normal" {

		deployments := k.ListDeployments("default")

		scheduleTypeName := strings.ReplaceAll(scheduleType, "_", "-") + "-go"
		deploymentName := helpers.CheckSliceContains(deployments, scheduleTypeName)
		if deploymentName == "" {
			serviceAccount := apiv1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      scheduleTypeName + "-deployment",
					Labels:    map[string]string{"app": scheduleTypeName + "-deployment", "component": scheduleTypeName + "-deployment"},
					Namespace: "default",
				},
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
				},
			}
			_, err := k.kubeClient.CoreV1().ServiceAccounts("default").Create(k.ctx, &serviceAccount, metav1.CreateOptions{})
			if err != nil && !strings.Contains(err.Error(), "exists") {
				k.kubeLogger.Error("failed to create service account", zap.Error(err))
				return "", err
			}
			clusterRole := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: scheduleTypeName + "node-pod-metrics-reader",
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{"metrics.k8s.io"},
						Resources: []string{"nodes"},
						Verbs:     []string{"get", "list", "watch"},
					},
					{
						APIGroups: []string{""},
						Resources: []string{"nodes", "pods"},
						Verbs:     []string{"get", "list", "watch"},
					},
					{
						APIGroups: []string{""},
						Resources: []string{"pods/binding", "events"},
						Verbs:     []string{"create"},
					},
				},
			}
			_, err = k.kubeClient.RbacV1().ClusterRoles().Create(k.ctx, clusterRole, metav1.CreateOptions{})
			if err != nil && !strings.Contains(err.Error(), "exists") {
				k.kubeLogger.Error("Failed to create ClusterRole", zap.Error(err))
				return "", err
			}
			// do it only once
			_, err = k.kubeClient.RbacV1().ClusterRoleBindings().Update(k.ctx, &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: scheduleTypeName + "-node-pod-metrics-binding",
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "ClusterRole",
					Name:     scheduleTypeName + "node-pod-metrics-reader",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind:      "ServiceAccount",
						Name:      scheduleTypeName + "-deployment",
						Namespace: "default",
					},
				},
			}, metav1.UpdateOptions{})
			if err != nil && !strings.Contains(err.Error(), "exists") {
				k.kubeLogger.Error("failed to update the  scheduler cluster role binding", zap.Error(err))
				return "", err
			}
			_, err = k.CreateDeployment(k.schedulerRegisterID+"/"+scheduleType, scheduleTypeName, "default", scheduleTypeName+"-deployment",
				"", int32(0), int32(1), []string{})
			if err != nil {
				k.kubeLogger.Error("failed to create deployment for scheduler", zap.Error(err), zap.String("schedule_type", scheduleType))
				return "", err
			}

		} else {
			k.kubeLogger.Warn("deployment already exists", zap.String("deployment", scheduleTypeName+"-deployment"))
		}

	}

	k.kubeLogger.Info("Created new/Already created namespace", zap.String("namespace", nameSpaceName))
	return nameSpaceName, nil
}

// ListNamespaces lists namespaces from kubernetes
func (k *KubernetesClient) ListNamespaces() []string {
	nsList, err := k.kubeClient.CoreV1().Namespaces().List(k.ctx, metav1.ListOptions{})
	if err != nil {
		k.kubeLogger.Error("failed to list namespaces", zap.Error(err))
		return []string{}
	}

	namespaces := make([]string, 0)
	for _, namespace := range nsList.Items {
		namespaces = append(namespaces, namespace.Name)
	}
	return namespaces
}

// DeleteNamespace deletes namespace for user
func (k *KubernetesClient) DeleteNamespace(userNameSpace string) error {
	namespaceClient := k.kubeClient.CoreV1().Namespaces()
	deletePolicy := metav1.DeletePropagationForeground
	err := namespaceClient.Delete(k.ctx, userNameSpace, metav1.DeleteOptions{
		PropagationPolicy: &deletePolicy,
	})
	if err != nil {
		k.kubeLogger.Error("failed to delete namespace", zap.String("user_namespace", userNameSpace), zap.Error(err))
		return err
	}
	k.kubeLogger.Info("Deleted namespace", zap.String("user_namespace", userNameSpace))
	return nil
}

func (k *KubernetesClient) CreateIngress(serviceName, namespace string, port int32, routePaths []string) (string, error) {
	ingressPaths := make([]networkingv1.HTTPIngressPath, 0)
	pathType := networkingv1.PathTypeImplementationSpecific
	for _, routePath := range routePaths {
		ingressPath := networkingv1.HTTPIngressPath{
			Path:     routePath,
			PathType: &pathType,
			Backend: networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: serviceName + "-service",
					Port: networkingv1.ServiceBackendPort{
						Number: port,
					},
				},
			},
		}
		ingressPaths = append(ingressPaths, ingressPath)
	}
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName + "-ingress",
			Namespace: namespace,
		},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{
				{
					Host: serviceName + ".conf",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: ingressPaths,
						},
					},
				},
			},
		},
	}
	ingressClient := k.kubeClient.NetworkingV1().Ingresses(namespace)
	ing, err := ingressClient.Create(k.ctx, ingress, metav1.CreateOptions{})
	if err != nil {
		k.kubeLogger.Error("failed to create ingress", zap.String("ingress_name", serviceName), zap.Error(err))
		return "", err
	}
	k.kubeLogger.Info("Created ingress", zap.String("ingress_name", ing.GetName()))

	for {
		resGetIng, err := ingressClient.Get(k.ctx, ing.GetName(), metav1.GetOptions{})
		if err != nil {
			k.kubeLogger.Error("failed to GET ingress", zap.String("ingress_name", ing.GetName()), zap.Error(err))
			return "", err
		}
		if len(resGetIng.Status.LoadBalancer.Ingress) > 0 {
			ingressIP := resGetIng.Status.LoadBalancer.Ingress[0].IP
			if ingressIP != "" {
				return ingressIP, nil
			}
		}
	}
}

// DeleteIngress deletes ingress from the required namespace
func (k *KubernetesClient) DeleteIngress(serviceName, namespace string) error {
	servicesClient := k.kubeClient.ExtensionsV1beta1().Ingresses(namespace)
	deletePolicy := metav1.DeletePropagationForeground
	err := servicesClient.Delete(k.ctx, serviceName+"-ingress", metav1.DeleteOptions{
		PropagationPolicy: &deletePolicy,
	})
	if err != nil {
		k.kubeLogger.Error("failed to delete ingress", zap.String("ingress", serviceName), zap.Error(err))
		return err
	}
	k.kubeLogger.Info("Deleted ingress", zap.String("ingress", serviceName))
	return nil
}

// CreateNodePort exposes port using NodePort
func (k *KubernetesClient) CreateNodePort(imageName, namespace string, port int32) (int32, error) {
	nodeport := apiv1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      imageName + "-service",
			Namespace: namespace,
			Labels: map[string]string{
				"app": imageName + "-deployment",
			},
		},
		Spec: apiv1.ServiceSpec{
			Ports: []apiv1.ServicePort{
				{
					TargetPort: intstr.FromInt32(port),
					Port:       port,
					Protocol:   apiv1.ProtocolTCP,
				},
			},
			Selector: map[string]string{
				"app": imageName + "-deployment",
			},
			Type: apiv1.ServiceTypeNodePort,
		},
	}
	svc, err := k.kubeClient.CoreV1().Services(namespace).Create(k.ctx, &nodeport, metav1.CreateOptions{})
	if err != nil {
		k.kubeLogger.Error("failed to create nodeport service", zap.Error(err))
		return 0, err
	}
	k.kubeLogger.Info("Created nodeport service", zap.String("nodeport_name", svc.GetName()))

	getSvc, err := k.kubeClient.CoreV1().Services(namespace).Get(k.ctx, svc.GetName(), metav1.GetOptions{})
	if err != nil {
		k.kubeLogger.Error("failed to get nodeport service", zap.Error(err))
		return 0, err
	}

	return getSvc.Spec.Ports[0].NodePort, err
}

// DeleteNodePort deletes nodeport from the required namespace
func (k *KubernetesClient) DeleteNodePort(serviceName, namespace string) error {
	servicesClient := k.kubeClient.CoreV1().Services(namespace)
	deletePolicy := metav1.DeletePropagationForeground
	err := servicesClient.Delete(k.ctx, serviceName+"-service", metav1.DeleteOptions{
		PropagationPolicy: &deletePolicy,
	})
	if err != nil {
		k.kubeLogger.Error("failed to delete nodeport", zap.String("nodeport_name", serviceName), zap.Error(err))
		return err
	}
	k.kubeLogger.Info("Deleted nodeort", zap.String("nodeort_name", serviceName))
	return nil
}

// CreateDeployment creates a deployment for image in the required namespace with a specific nr of replicas
func (k *KubernetesClient) CreateDeployment(tagName, imageName, namespace, serviceName,
	schedulerName string, portNr, nrReplicas int32, routePaths []string) (string, error) {
	var cpuLimit, memLimit, cpuReq, memReq string
	if schedulerName != "" {
		cpuLimit = "500m"
		memLimit = "128Mi"
		cpuReq = "250m"
		memReq = "64Mi"
	}

	deploymentsClient := k.kubeClient.AppsV1().Deployments(namespace)
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: imageName + "-deployment",
			Labels: map[string]string{
				"app": imageName + "-deployment",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &nrReplicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": imageName + "-deployment",
				},
			},
			Template: apiv1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": imageName + "-deployment",
					},
				},
				Spec: apiv1.PodSpec{
					Containers: []apiv1.Container{
						{
							Name:  imageName + "-deployment",
							Image: tagName,
						},
					},
				},
			},
		},
	}

	if serviceName != "" {
		deployment.Spec.Template.Spec.ServiceAccountName = serviceName
	}
	if schedulerName != "" {
		deployment.Spec.Template.Spec.SchedulerName = schedulerName + "-deployment"
	}
	if portNr != int32(0) {
		deployment.Spec.Template.Spec.Containers[0].Ports = []apiv1.ContainerPort{{HostPort: portNr, ContainerPort: portNr}}
	}
	if schedulerName != "" {
		deployment.Spec.Template.Spec.Containers[0].Resources.Limits = apiv1.ResourceList{
			"cpu":    resource.MustParse(cpuLimit),
			"memory": resource.MustParse(memLimit),
		}
		deployment.Spec.Template.Spec.Containers[0].Resources.Requests = apiv1.ResourceList{
			"cpu":    resource.MustParse(cpuReq),
			"memory": resource.MustParse(memReq),
		}
	}
	result, err := deploymentsClient.Create(k.ctx, deployment, metav1.CreateOptions{})
	if err != nil && !strings.Contains(err.Error(), "exists") {
		k.kubeLogger.Error("failed to create deployment", zap.Error(err))
		return "", err
	}
	var publicIp string
	if portNr != int32(0) {
		exposedPort, err := k.CreateNodePort(imageName, namespace, portNr)
		if err != nil {
			return "", err
		}
		loadBalancerIP, err := k.CreateIngress(imageName, namespace, portNr, routePaths)
		if err != nil {
			return "", err
		}
		publicIp = loadBalancerIP + ":" + strconv.Itoa(int(exposedPort))

	}
	k.kubeLogger.Info("Created deployment", zap.String("deployment_name", result.GetName()))
	return publicIp, nil
}

// ListDeployments lists deployments
func (k *KubernetesClient) ListDeployments(namespace string) []string {
	deployList, err := k.kubeClient.AppsV1().Deployments(namespace).List(k.ctx, metav1.ListOptions{})
	if err != nil {
		k.kubeLogger.Error("failed to list deployments", zap.Error(err))
		return []string{}
	}
	deployments := make([]string, 0)
	for _, deployment := range deployList.Items {
		deployments = append(deployments, deployment.Name)
	}
	return deployments

}

// UpdateDeployments updates deployment with nrReplicas and new Image
func (k *KubernetesClient) UpdateDeployment(deployName, namespace, newImage, memUsage, maxMemUsage, cpuUsage,
	maxCpuUsage string, nrReplicas int32) error {

	deploymentsClient := k.kubeClient.AppsV1().Deployments(namespace)

	retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		// Retrieve the latest version of Deployment before attempting update
		// RetryOnConflict uses exponential backoff to avoid exhausting the apiserver
		result, getErr := deploymentsClient.Get(k.ctx, deployName+"-deployment", metav1.GetOptions{})
		if getErr != nil {
			k.kubeLogger.Error("failed to get deployment", zap.Error(getErr))
			return getErr
		}
		if nrReplicas != int32(0) {
			result.Spec.Replicas = &nrReplicas
		}
		if newImage != "" {
			result.Spec.Template.Spec.Containers[0].Image = newImage
		}
		if memUsage != "" && maxMemUsage != "" && cpuUsage != "" && maxCpuUsage != "" {
			intCpuUsage, _ := strconv.ParseInt(cpuUsage[:len(cpuUsage)-1], 0, 64)
			intMaxCpuUsage, _ := strconv.ParseInt(maxCpuUsage[:len(maxCpuUsage)-1], 0, 64)
			intMemUsage, _ := strconv.ParseInt(memUsage[:len(memUsage)-2], 0, 64)
			intMaxMemUsage, _ := strconv.ParseInt(maxMemUsage[:len(maxMemUsage)-2], 0, 64)

			if intCpuUsage > intMaxCpuUsage {
				return fmt.Errorf("cpu usage should be less or equal then max cpu usage")
			}
			if intMemUsage > intMaxMemUsage {
				return fmt.Errorf("mem usage should be less or equal then max mem usage")
			}
			result.Spec.Template.Spec.Containers[0].Resources.Limits = apiv1.ResourceList{
				"cpu":    resource.MustParse(maxCpuUsage),
				"memory": resource.MustParse(maxMemUsage),
			}
			result.Spec.Template.Spec.Containers[0].Resources.Requests = apiv1.ResourceList{
				"cpu":    resource.MustParse(cpuUsage),
				"memory": resource.MustParse(memUsage),
			}
		} else {
			k.kubeLogger.Debug("missing values to update cpu and mem usage on deployment")
		}
		_, updateErr := deploymentsClient.Update(k.ctx, result, metav1.UpdateOptions{})
		if updateErr != nil {
			k.kubeLogger.Error("failed to update deployment", zap.Error(updateErr))
		}
		return updateErr
	})
	if retryErr != nil {
		k.kubeLogger.Error("failed on retrier", zap.Error(retryErr))
		return retryErr
	}
	k.kubeLogger.Debug("Succesfully updated deployment", zap.String("deployment", deployName))
	return nil
}

// DeleteDeployment deletes deployment from the required namespace
func (k *KubernetesClient) DeleteDeployment(deployName, namespace string) error {
	deploymentsClient := k.kubeClient.AppsV1().Deployments(namespace)
	deletePolicy := metav1.DeletePropagationForeground
	err := deploymentsClient.Delete(k.ctx, deployName+"-deployment", metav1.DeleteOptions{
		PropagationPolicy: &deletePolicy,
	})
	if err != nil {
		k.kubeLogger.Error("failed to delete deployment", zap.String("deploy_name", deployName), zap.Error(err))
		return err
	}
	k.kubeLogger.Info("Deleted deployment", zap.String("deployment_name", deployName))
	return nil
}

// ListPods lists pods from a namespace from kubernetes
func (k *KubernetesClient) ListPods(namespace string) []string {
	podsList, err := k.kubeClient.CoreV1().Pods(namespace).List(k.ctx, metav1.ListOptions{})
	if err != nil {
		k.kubeLogger.Error("failed to list pods", zap.Error(err))
		return []string{}
	}
	pods := make([]string, 0)
	for _, pod := range podsList.Items {
		pods = append(pods, pod.Name)
	}
	return pods
}

// GetLogsForPodName iterates through replicas of podName and returns logs
func (k *KubernetesClient) GetLogsForPodName(deploymentName, namespace string) ([]string, error) {
	logList := make([]string, 0)
	podsClient := k.kubeClient.CoreV1().Pods(namespace)
	for {
		pods, err := podsClient.List(k.ctx, metav1.ListOptions{LabelSelector: "app=" + deploymentName})
		if err != nil {
			k.kubeLogger.Error("failed to list pods", zap.Error(err))
			return nil, err
		}
		for _, pod := range pods.Items {

			if pod.Status.Phase == apiv1.PodPending {
				k.kubeLogger.Warn("waiting for pod to be ready")
			} else {
				logFromPod := podsClient.GetLogs(pod.Name, &apiv1.PodLogOptions{})
				podLogs, err := logFromPod.Stream(k.ctx)
				if err != nil {
					k.kubeLogger.Error("failed to get stream", zap.Error(err))
					return nil, err
				}
				defer podLogs.Close()

				buf := new(bytes.Buffer)
				_, err = io.Copy(buf, podLogs)
				if err != nil {
					k.kubeLogger.Error("error in copy information from podLogs to buf", zap.Error(err))
					return nil, err
				}
				str := buf.String()
				logList = append(logList, str)
			}
		}
		if len(logList) == 0 {
			return nil, fmt.Errorf("no pods found")
		} else {
			break
		}

	}
	return logList, nil
}

// GetPodFile retrieves file from pod
func (k *KubernetesClient) GetPodFile(fileName, appName, deploymentName, namespace string) ([]byte, error) {
	containerName := ""
	podName := ""
	podsClient := k.kubeClient.CoreV1().Pods(namespace)
	for {
		pods, err := podsClient.List(k.ctx, metav1.ListOptions{LabelSelector: "app=" + deploymentName})
		if err != nil {
			k.kubeLogger.Error("failed to list pods", zap.Error(err))
			return nil, err
		}
		for _, pod := range pods.Items {

			if pod.Status.Phase == apiv1.PodPending {
				k.kubeLogger.Warn("waiting for pod to be ready")
			} else {
				containerName = pod.Spec.Containers[0].Name
				podName = pod.Name
			}
		}
		if containerName == "" {
			k.kubeLogger.Warn("no pods found")
			return nil, fmt.Errorf("no pods found")
		} else {
			break
		}

	}
	cmd := []string{"kubectl", "cp", "-n", namespace, podName + ":" + fileName, fileName}
	command := exec.Command(cmd[0], cmd[1:]...)

	var out bytes.Buffer
	command.Stdout = &out
	err := command.Run()
	if err != nil {
		k.kubeLogger.Error("failed to run kubectl cp command", zap.Error(err))
		return nil, err
	}
	fileContent, err := os.ReadFile(fileName)
	if err != nil {
		k.kubeLogger.Error("failed to read file", zap.Error(err))
		return nil, err
	}
	return fileContent, nil

}

// CreateAutoScaler creates a horizontal pod auto scaler for deploymentName
func (k *KubernetesClient) CreateAutoScaler(deploymentName, namespace string, minReplicas, maxReplicas int32) (*hpav2.HorizontalPodAutoscaler, error) {
	memoryTargetUtilization := int32(70)
	cpuTargetUtilization := int32(50)
	autoscaler := &hpav2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deploymentName + "-hpa",
			Namespace: namespace,
		},
		Spec: hpav2.HorizontalPodAutoscalerSpec{

			ScaleTargetRef: hpav2.CrossVersionObjectReference{
				Kind:       "Deployment",
				Name:       deploymentName + "-deployment",
				APIVersion: "apps/v1",
			},
			MinReplicas: &minReplicas,
			MaxReplicas: maxReplicas,
			Metrics: []hpav2.MetricSpec{
				{
					Type: hpav2.ResourceMetricSourceType,
					Resource: &hpav2.ResourceMetricSource{
						Name: "cpu",
						Target: hpav2.MetricTarget{
							Type:               "Utilization",
							AverageUtilization: ptr.To(cpuTargetUtilization),
						},
					},
				},
				{
					Type: hpav2.ResourceMetricSourceType,
					Resource: &hpav2.ResourceMetricSource{
						Name: "memory",
						Target: hpav2.MetricTarget{
							Type:               "Utilization",
							AverageUtilization: ptr.To(memoryTargetUtilization),
						},
					},
				},
			},
		},
	}
	apply, err := k.kubeClient.AutoscalingV2().HorizontalPodAutoscalers(namespace).
		Create(k.ctx, autoscaler, metav1.CreateOptions{})

	if err != nil {
		k.kubeLogger.Error("failed to create autoscaler", zap.Error(err))
		return nil, err
	}

	k.kubeLogger.Debug("Sucesfully created autoscaler", zap.String("hpa_name", apply.GetName()))

	return apply, nil
}

// UpdateAutoScaler updates auto scaler with min and max replicas
func (k *KubernetesClient) UpdateAutoScaler(deploymentName, namespace string, minReplicas, maxReplicas int32) error {
	retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		// Retrieve the latest version of HPA before attempting update
		// RetryOnConflict uses exponential backoff to avoid exhausting the apiserver
		result, getErr := k.kubeClient.AutoscalingV2().HorizontalPodAutoscalers(namespace).Get(k.ctx, deploymentName+"-hpa", metav1.GetOptions{})
		if getErr != nil {
			k.kubeLogger.Error("failed to get hpa", zap.Error(getErr))
			return getErr
		}
		if minReplicas != int32(0) {
			//update min replica count
			result.Spec.MinReplicas = &minReplicas
		}
		if maxReplicas != int32(0) {
			//update max replica count
			result.Spec.MaxReplicas = maxReplicas
		}

		_, updateErr := k.kubeClient.AutoscalingV2().HorizontalPodAutoscalers(namespace).Update(k.ctx, result, metav1.UpdateOptions{})
		if updateErr != nil {
			k.kubeLogger.Error("failed to update hpa", zap.Error(updateErr))
			return updateErr
		}
		return updateErr
	})
	if retryErr != nil {
		k.kubeLogger.Error("failed on retrier", zap.Error(retryErr))
		return retryErr
	}

	k.kubeLogger.Debug("Sucesfully updated autoscaler", zap.String("app_name", deploymentName))
	return nil
}

// DeleteAutoScaler deletes autoscaler from the required namespace
func (k *KubernetesClient) DeleteAutoScaler(autoScalerName, namespace string) error {
	autoScalersClient := k.kubeClient.AutoscalingV2().HorizontalPodAutoscalers(namespace)
	deletePolicy := metav1.DeletePropagationForeground
	err := autoScalersClient.Delete(k.ctx, autoScalerName+"-hpa", metav1.DeleteOptions{
		PropagationPolicy: &deletePolicy,
	})
	if err != nil {
		k.kubeLogger.Error("failed to delete autoscaler", zap.String("autoscaler_name", autoScalerName), zap.Error(err))
		return err
	}
	k.kubeLogger.Info("Deleted autoscaler", zap.String("autoscaler_name", autoScalerName))
	return nil
}
