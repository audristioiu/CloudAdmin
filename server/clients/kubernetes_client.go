package clients

import (
	"bytes"
	"cloudadmin/helpers"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	hpav1 "k8s.io/api/autoscaling/v1"
	apiv1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	client "k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
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
func (k *KubernetesClient) CreateNamespace(userName, scheduleType, fileName string, fileData []byte) (string, error) {

	var nameSpaceName string

	nr := strconv.Itoa(helpers.GetRandomInt())
	namespaceClient := k.kubeClient.CoreV1().Namespaces()
	newNamespace := &apiv1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace-" + userName + nr,
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

	_, err = k.kubeClient.RbacV1().Roles(nameSpaceName).Create(k.ctx, &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      nameSpaceName + "-role",
			Namespace: nameSpaceName,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{rbacv1.APIGroupAll},
				Resources: []string{rbacv1.ResourceAll},
				Verbs:     []string{rbacv1.VerbAll},
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		k.kubeLogger.Error("failed to create role", zap.Error(err))
		return "", err
	}

	_, err = k.kubeClient.RbacV1().RoleBindings(nameSpaceName).Create(k.ctx, &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      nameSpaceName + "-role-bind",
			Namespace: nameSpaceName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     nameSpaceName + "-role",
		},
		Subjects: []rbacv1.Subject{
			{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "User",
				Name:     userName,
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		k.kubeLogger.Error("failed to create role binding", zap.Error(err))
		return "", err
	}

	scheduleTypeName := strings.ReplaceAll(scheduleType, "_", "-")
	serviceAccount := apiv1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scheduleTypeName,
			Namespace: nameSpaceName,
			Labels:    map[string]string{"app": scheduleTypeName, "component": scheduleTypeName},
		},
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
	}

	_, err = k.kubeClient.CoreV1().ServiceAccounts(nameSpaceName).Create(k.ctx, &serviceAccount, metav1.CreateOptions{})
	if err != nil {
		k.kubeLogger.Error("failed to create service account", zap.Error(err))
		return "", err
	}
	// do it only once
	_, err = k.kubeClient.RbacV1().ClusterRoleBindings().Update(k.ctx, &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scheduleTypeName,
			Namespace: nameSpaceName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "system:kube-scheduler",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      scheduleTypeName,
				Namespace: nameSpaceName,
			},
		},
	}, metav1.UpdateOptions{})
	if err != nil {
		k.kubeLogger.Error("failed to update the random scheduler cluster role binding", zap.Error(err))
		return "", err
	}

	var configMapName string

	if scheduleType == "rr_sjf" {
		configMapName, err = k.CreateConfigMap(nameSpaceName, fileName, fileData)
		if err != nil {
			return "", err
		}
	}

	schedulerCommands := []string{
		"--leader-elect=true",
		"--scheduler-name=" + scheduleTypeName,
		"--lock-object-name=" + scheduleTypeName,
	}

	err = k.CreateDeployment(k.schedulerRegisterID+"/"+scheduleType, scheduleTypeName+"-go", nameSpaceName, scheduleTypeName, "",
		configMapName, schedulerCommands, int32(0), int32(1))
	if err != nil {
		k.kubeLogger.Error("failed to create deployment for scheduler", zap.Error(err), zap.String("schedule_type", scheduleType))
		return "", err
	}

	time.Sleep(5 * time.Second)
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

// todo de testat
// CreateDeployment creates a deployment for image in the required namespace with a specific nr of replicas
func (k *KubernetesClient) CreateDeployment(tagName, imageName, namespace, serviceName, schedulerName,
	configMapName string, schedulerCommands []string, portNr, nrReplicas int32) error {
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
	if len(schedulerCommands) > 0 {
		deployment.Spec.Template.Spec.Containers[0].Command = schedulerCommands
	}
	if serviceName != "" {
		deployment.Spec.Template.Spec.ServiceAccountName = serviceName
	}
	if schedulerName != "" {
		deployment.Spec.Template.Spec.SchedulerName = schedulerName
	}
	if portNr != int32(0) {
		deployment.Spec.Template.Spec.Containers[0].Ports = []apiv1.ContainerPort{{HostPort: portNr}}
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
					HostPath: &apiv1.HostPathVolumeSource{
						Path: "/data",
					},
				},
			},
		}
	}

	result, err := deploymentsClient.Create(k.ctx, deployment, metav1.CreateOptions{})
	if err != nil {
		k.kubeLogger.Error("failed to create deployment", zap.Error(err))
		return err
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
		result, getErr := deploymentsClient.Get(context.TODO(), deployName+"-deployment", metav1.GetOptions{})
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

// CreateAutoScaler creates a horizontal pod auto scaler for deploymentName
func (k *KubernetesClient) CreateAutoScaler(deploymentName string, namespace string, minReplicas, maxReplicas int32) (*hpav1.HorizontalPodAutoscaler, error) {
	targetUtilization := int32(70)
	autoscaler := &hpav1.HorizontalPodAutoscaler{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "autoscaling/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      deploymentName + "-hpa",
			Namespace: namespace,
		},
		Spec: hpav1.HorizontalPodAutoscalerSpec{
			ScaleTargetRef: hpav1.CrossVersionObjectReference{
				Kind:       "Deployment",
				Name:       deploymentName + "-development",
				APIVersion: "apps/v1",
			},
			MinReplicas:                    &minReplicas,
			MaxReplicas:                    maxReplicas,
			TargetCPUUtilizationPercentage: &targetUtilization,
		},
	}

	apply, err := k.kubeClient.AutoscalingV1().HorizontalPodAutoscalers(namespace).
		Create(k.ctx, autoscaler, metav1.CreateOptions{})

	if err != nil {
		k.kubeLogger.Error("failed to create autoscaler", zap.Error(err))
		return nil, err
	}

	k.kubeLogger.Debug("Sucesfully created autoscaler", zap.String("hpa_name", apply.GetName()))

	return apply, nil
}

// CreateService exposes deploymentName as a service
func (k *KubernetesClient) CreateService(deploymentName string, namespace string) (*apiv1.Service, error) {
	port, _ := helpers.GetFreePort()
	service := apiv1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:   deploymentName + "-service",
			Labels: map[string]string{"run": deploymentName},
		},
		Spec: apiv1.ServiceSpec{
			Ports: []apiv1.ServicePort{
				{
					Port: int32(port),
				},
			},
			Selector: map[string]string{"run": deploymentName},
		},
	}

	apply, err := k.kubeClient.CoreV1().Services(namespace).Create(k.ctx, &service, metav1.CreateOptions{})
	if err != nil {
		k.kubeLogger.Error("failed to expose service", zap.Error(err))
		return nil, err
	}

	k.kubeLogger.Debug("Sucesfully create service", zap.String("service_name", apply.GetName()))

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
