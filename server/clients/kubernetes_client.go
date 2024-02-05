package clients

import (
	"bytes"
	"cloudadmin/helpers"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	hpav2 "k8s.io/api/autoscaling/v2"
	apiv1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	client "k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/pointer"
)

// KubernetesClient represents info about Kubernetes client
type KubernetesClient struct {
	ctx                 context.Context
	kubeClient          *client.Clientset
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
	return &KubernetesClient{
		ctx:                 ctx,
		kubeLogger:          logger,
		kubeClient:          clientset,
		schedulerRegisterID: schedulerID,
	}
}

// CreateNamespace creates new namespace for user
func (k *KubernetesClient) CreateNamespace(userName, scheduleType string) (string, error) {

	var nameSpaceName string

	nr := strconv.Itoa(helpers.GetRandomInt())
	newUserName := strings.ReplaceAll(userName, "_", "-")
	namespaceClient := k.kubeClient.CoreV1().Namespaces()
	newNamespace := &apiv1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace-" + newUserName + nr,
		},
	}
	resNameSpace, err := namespaceClient.Create(k.ctx, newNamespace, metav1.CreateOptions{})
	if err != nil {
		k.kubeLogger.Error("failed to create new namespace for user", zap.String("user_name", userName), zap.Error(err))
		if !strings.Contains(err.Error(), "already exists") {
			nameSpaceName = "namespace-" + userName + nr
		} else {
			return "", err
		}

	} else {
		nameSpaceName = resNameSpace.GetName()
	}
	if scheduleType != "normal" {

		scheduleTypeName := strings.ReplaceAll(scheduleType, "_", "-") + "-go"
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
		// do it only once
		_, err = k.kubeClient.RbacV1().ClusterRoleBindings().Update(k.ctx, &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: scheduleTypeName + "-deployment",
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     "system:kube-scheduler",
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
			k.kubeLogger.Error("failed to update the random scheduler cluster role binding", zap.Error(err))
			return "", err
		}

		//todo
		schedulerCommands := []string{
			// "--scheduler-name=" + scheduleTypeName+"-deployment",
			// "--lock-object-name=" + scheduleTypeName+"-deployment",
		}

		err = k.CreateDeployment(k.schedulerRegisterID+"/"+scheduleType, scheduleTypeName, "default", scheduleTypeName+"-deployment", "",
			"", schedulerCommands, int32(0), int32(1))
		if err != nil && !strings.Contains(err.Error(), "exists") {
			k.kubeLogger.Error("failed to create deployment for scheduler", zap.Error(err), zap.String("schedule_type", scheduleType))
			return "", err
		}
	}

	k.kubeLogger.Info("Created new/Already created namespace", zap.String("namespace", nameSpaceName))
	return nameSpaceName, nil
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

// CreateConfigMap creates a config map used for pods in namespace
func (k *KubernetesClient) CreateConfigMap(namespace, fileName string, marshalledTaskData []byte) (string, error) {
	cfMap, err := k.kubeClient.CoreV1().ConfigMaps(namespace).Create(k.ctx, &apiv1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind: "ConfigMap",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rr-sjf-config-map",
			Namespace: namespace,
		},
		BinaryData: map[string][]byte{
			fileName: marshalledTaskData,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		k.kubeLogger.Error("failed to create configmap", zap.Error(err))
		return "", err
	}
	k.kubeLogger.Info("Created config map", zap.String("config_map_name", cfMap.GetName()))
	return cfMap.GetName(), nil
}

func (k *KubernetesClient) PortForward(imageName, namespace string, sourcePort int32) error {
	//todo when done
	return nil
}

// CreateNodePort exposes port using NodePort
func (k *KubernetesClient) CreateNodePort(imageName, namespace string, port int32) error {
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
		k.kubeLogger.Error("failed to create nodeort service", zap.Error(err))
		return err
	}
	k.kubeLogger.Info("Created nodeport service", zap.String("deployment_name", svc.GetName()))
	return nil
}

// CreateDeployment creates a deployment for image in the required namespace with a specific nr of replicas
func (k *KubernetesClient) CreateDeployment(tagName, imageName, namespace, serviceName, schedulerName,
	configMapName string, schedulerCommands []string, portNr, nrReplicas int32) error {
	cpuLimit := "500"
	memLimit := "500"
	cpuReq := "100"
	memReq := "100"
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
							Resources: apiv1.ResourceRequirements{
								Limits: apiv1.ResourceList{
									"cpu":    resource.MustParse(cpuLimit),
									"memory": resource.MustParse(memLimit),
								},
								Requests: apiv1.ResourceList{
									"cpu":    resource.MustParse(cpuReq),
									"memory": resource.MustParse(memReq),
								},
							},
						},
					},
				},
			},
		},
	}
	// todo
	// if len(schedulerCommands) > 0 {
	// 	deployment.Spec.Template.Spec.Containers[0].Command = schedulerCommands
	// }
	if serviceName != "" {
		deployment.Spec.Template.Spec.ServiceAccountName = serviceName
	}
	if schedulerName != "" {
		deployment.Spec.Template.Spec.SchedulerName = schedulerName + "-deployment"
	}
	if portNr != int32(0) {
		deployment.Spec.Template.Spec.Containers[0].Ports = []apiv1.ContainerPort{{HostPort: portNr, ContainerPort: portNr}}
	}

	if configMapName != "" {
		deployment.Spec.Template.Spec.Containers[0].VolumeMounts = []apiv1.VolumeMount{
			{
				Name:      "config-volume",
				MountPath: "/config-volume",
			},
		}
		deployment.Spec.Template.Spec.Volumes = []apiv1.Volume{
			{
				Name: "config-volume",
				VolumeSource: apiv1.VolumeSource{
					ConfigMap: &apiv1.ConfigMapVolumeSource{
						LocalObjectReference: apiv1.LocalObjectReference{
							Name: configMapName,
						},
					},
				},
			},
		}
	}

	result, err := deploymentsClient.Create(k.ctx, deployment, metav1.CreateOptions{})
	if err != nil && !strings.Contains(err.Error(), "exists") {
		k.kubeLogger.Error("failed to create deployment", zap.Error(err))
		return err
	}

	if portNr != int32(0) {
		deployment.Spec.Template.Spec.Containers[0].Ports = []apiv1.ContainerPort{{HostPort: portNr, ContainerPort: portNr}}
		err := k.CreateNodePort(imageName, namespace, portNr)
		if err != nil {
			return err
		}
		// err = k.PortForward(imageName, namespace, portNr)
		// if err != nil {
		// 	return err
		// }

	}
	k.kubeLogger.Info("Created deployment", zap.String("deployment_name", result.GetName()))
	return nil
}

// UpdateDeployments updates deployment with nrReplicas and new Image
func (k *KubernetesClient) UpdateDeployment(deployName, namespace, newImage string, nrReplicas int32) {

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
			//update replica count
			result.Spec.Replicas = &nrReplicas
		}
		if newImage != "" {
			// change image version
			result.Spec.Template.Spec.Containers[0].Image = newImage
		}

		_, updateErr := deploymentsClient.Update(k.ctx, result, metav1.UpdateOptions{})
		if updateErr != nil {
			k.kubeLogger.Error("failed to update hpa", zap.Error(updateErr))
		}
		return updateErr
	})
	if retryErr != nil {
		k.kubeLogger.Error("failed on retrier", zap.Error(retryErr))
		return
	}
	k.kubeLogger.Debug("Succesfully updated deployment", zap.String("deployment", deployName))
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

// CreateAutoScaler creates a horizontal pod auto scaler for deploymentName (todo not working)
func (k *KubernetesClient) CreateAutoScaler(deploymentName string, namespace string, minReplicas, maxReplicas int32) (*hpav2.HorizontalPodAutoscaler, error) {
	targetUtilization := int32(70)
	autoscaler := &hpav2.HorizontalPodAutoscaler{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "autoscaling/v1",
		},
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
							AverageUtilization: pointer.Int32(targetUtilization),
						},
					},
				},
				{
					Type: hpav2.ResourceMetricSourceType,
					Resource: &hpav2.ResourceMetricSource{
						Name: "memory",
						Target: hpav2.MetricTarget{
							Type:               "Utilization",
							AverageUtilization: pointer.Int32(targetUtilization),
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
func (k *KubernetesClient) UpdateAutoScaler(deploymentName string, namespace string, minReplicas, maxReplicas int32) {
	retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		// Retrieve the latest version of HPA before attempting update
		// RetryOnConflict uses exponential backoff to avoid exhausting the apiserver
		result, getErr := k.kubeClient.AutoscalingV1().HorizontalPodAutoscalers(namespace).Get(k.ctx, deploymentName+"-hpa", metav1.GetOptions{})
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

		_, updateErr := k.kubeClient.AutoscalingV1().HorizontalPodAutoscalers(namespace).Update(k.ctx, result, metav1.UpdateOptions{})
		if updateErr != nil {
			k.kubeLogger.Error("failed to update hpa", zap.Error(updateErr))
			return updateErr
		}
		return updateErr
	})
	if retryErr != nil {
		k.kubeLogger.Error("failed on retrier", zap.Error(retryErr))
		return
	}

	k.kubeLogger.Debug("Sucesfully updated autoscaler", zap.String("app_name", deploymentName))
}
