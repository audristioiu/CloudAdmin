package api

import (
	"cloudadmin/clients"
	"cloudadmin/domain"
	"cloudadmin/repositories"
	"context"
	"net"
	"net/http"

	"github.com/VirusTotal/vt-go"
	"github.com/dgraph-io/ristretto"
	restfulspec "github.com/emicklei/go-restful-openapi/v2"
	"github.com/emicklei/go-restful/v3"
	"go.uber.org/zap"
)

const (
	registerPath            = "/register"
	loginPath               = "/login"
	userPath                = "/user"
	otpPath                 = "/otp"
	appPath                 = "/app"
	aggregatesPath          = "/aggregates"
	schedulePath            = "/schedule"
	getPodResultPath        = "/getresults"
	getPodFilePath          = "/getpodfile"
	grafanaDataSourcePath   = "/grafana/datasource"
	grafanaAlertPath        = "/grafana/alert"
	grafanaUpdateAlertPath  = "/grafana/update_alert"
	grafanaAlertTriggerPath = "/grafana/alert_trigger"
	formSubmitPath          = "/form_submit"
	formStatisticsPath      = "/form_stats"
)

// API represents the object used for the api, api handlers and contains context and storage + local cache + profiling service + clients
type API struct {
	ctx                   context.Context
	psqlRepo              *repositories.PostgreSqlRepo
	apiCache              *ristretto.Cache
	apiLogger             *zap.Logger
	profiler              *repositories.ProfilingService
	dockerClient          *clients.DockerClient
	kubeClient            *clients.KubernetesClient
	s3Client              *clients.S3Client
	graphiteAddr          *net.TCPAddr
	requestCount          map[string]int
	maxRequestPerMinute   int
	dockerRegID           string
	grafanaDataSourceUUID string
	grafanaFolderUID      string
	vtClient              *vt.Client
	grafanaHTTPClient     *clients.GrafanaClient
}

// NewAPI returns an API object
func NewAPI(ctx context.Context, postgresRepo *repositories.PostgreSqlRepo, cache *ristretto.Cache, logger *zap.Logger,
	cpuProfiler *repositories.ProfilingService, dockerClient *clients.DockerClient, kubeClient *clients.KubernetesClient, s3Client *clients.S3Client,
	graphiteAddr *net.TCPAddr, requestCount map[string]int, maxRequestPerMinute int, dockerRegID, grafanaDataSourceUUID, grafanaFolderUID string,
	vtClient *vt.Client, grafanaHTTPClient *clients.GrafanaClient) *API {
	return &API{
		ctx:                   ctx,
		psqlRepo:              postgresRepo,
		apiCache:              cache,
		apiLogger:             logger,
		profiler:              cpuProfiler,
		dockerClient:          dockerClient,
		kubeClient:            kubeClient,
		s3Client:              s3Client,
		graphiteAddr:          graphiteAddr,
		requestCount:          requestCount,
		maxRequestPerMinute:   maxRequestPerMinute,
		dockerRegID:           dockerRegID,
		grafanaDataSourceUUID: grafanaDataSourceUUID,
		grafanaFolderUID:      grafanaFolderUID,
		vtClient:              vtClient,
		grafanaHTTPClient:     grafanaHTTPClient,
	}
}

// RegisterRoutes adds routes for all endpoints
func (api *API) RegisterRoutes(ws *restful.WebService) {
	tags := []string{"users"}
	ws.Route(
		ws.
			POST(registerPath+userPath).
			Doc("Register user").
			Reads(domain.UserData{}).
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			To(api.UserRegister).
			Writes(domain.QueryResponse{}).
			Returns(http.StatusOK, "OK", domain.QueryResponse{}).
			Returns(http.StatusFound, "Already found", domain.ErrorResponse{}).
			Returns(http.StatusBadRequest, "Bad Request", domain.ErrorResponse{}))

	ws.Route(
		ws.
			POST(loginPath).
			Doc("Login user").
			Param(ws.QueryParameter("old_password", "old pass for changing password").DataType("boolean").Required(false).AllowEmptyValue(true)).
			Reads(domain.UserData{}).
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			To(api.UserLogin).
			Writes(domain.UserData{}).
			Returns(http.StatusOK, "OK", domain.UserData{}).
			Returns(http.StatusNotFound, "User Not Found", domain.ErrorResponse{}).
			Returns(http.StatusBadRequest, "Bad Request", domain.ErrorResponse{}))
	ws.Route(
		ws.
			GET(userPath+"/{username}").
			Doc("Retrieve user profile").
			Param(ws.PathParameter("username", "username of the account").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.HeaderParameter("USER-AUTH", "role used for auth").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.HeaderParameter("USER-UUID", "user unique id").DataType("string").Required(true).AllowEmptyValue(false)).
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Filter(api.BasicAuthenticate).
			Filter(api.CompressedEncodingFilter).
			To(api.GetUserProfile).
			Writes(domain.UserData{}).
			Returns(http.StatusOK, "OK", domain.UserData{}).
			Returns(http.StatusNotFound, "User Not Found", domain.ErrorResponse{}).
			Returns(http.StatusBadRequest, "Bad Request", domain.ErrorResponse{}))
	ws.Route(
		ws.
			PUT(userPath).
			Doc("Update user profile").
			Reads(domain.UserData{}).
			Param(ws.HeaderParameter("USER-AUTH", "role used for auth").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.HeaderParameter("USER-UUID", "user unique id").DataType("string").Required(true).AllowEmptyValue(false)).
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Filter(api.BasicAuthenticate).
			Filter(api.CompressedEncodingFilter).
			Writes(domain.QueryResponse{}).
			To(api.UpdateUserProfile).
			Returns(http.StatusOK, "OK", domain.QueryResponse{}).
			Returns(http.StatusNotFound, "User Not Found", domain.ErrorResponse{}).
			Returns(http.StatusBadRequest, "Bad Request", domain.ErrorResponse{}))
	ws.Route(
		ws.
			DELETE(userPath).
			Doc("Delete user").
			Param(ws.HeaderParameter("USER-AUTH", "role used for auth").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.HeaderParameter("USER-UUID", "user unique id").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("usernames", "usernames to delete").DataType("string").Required(true).AllowEmptyValue(false).AllowMultiple(true)).
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Filter(api.BasicAuthenticate).
			Filter(api.CompressedEncodingFilter).
			To(api.DeleteUser).
			Writes(domain.QueryResponse{}).
			Returns(http.StatusOK, "OK", domain.QueryResponse{}).
			Returns(http.StatusNotFound, "User Not Found", domain.ErrorResponse{}).
			Returns(http.StatusBadRequest, "Bad Request", domain.ErrorResponse{}))
	ws.Route(
		ws.
			POST(otpPath+"/generate").
			Doc("Generate OTP token").
			Param(ws.HeaderParameter("USER-AUTH", "role used for auth").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.HeaderParameter("USER-UUID", "user unique id").DataType("string").Required(true).AllowEmptyValue(false)).
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Filter(api.BasicAuthenticate).
			Filter(api.CompressedEncodingFilter).
			To(api.GenerateOTPToken).
			Writes(domain.GenerateOTPResponse{}).
			Returns(http.StatusOK, "OK", domain.GenerateOTPResponse{}).
			Returns(http.StatusNotFound, "User Not Found", domain.ErrorResponse{}).
			Returns(http.StatusBadRequest, "Bad Request", domain.ErrorResponse{}))
	ws.Route(
		ws.
			POST(otpPath+"/verify").
			Doc("Verfiy and enable OTP token").
			Reads(domain.OTPInput{}).
			Param(ws.HeaderParameter("USER-AUTH", "role used for auth").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.HeaderParameter("USER-UUID", "user unique id").DataType("string").Required(true).AllowEmptyValue(false)).
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Filter(api.BasicAuthenticate).
			Filter(api.CompressedEncodingFilter).
			To(api.VerifyOTPToken).
			Writes(domain.QueryResponse{}).
			Returns(http.StatusOK, "OK", domain.QueryResponse{}).
			Returns(http.StatusNotFound, "User Not Found", domain.ErrorResponse{}).
			Returns(http.StatusBadRequest, "Bad Request", domain.ErrorResponse{}))
	ws.Route(
		ws.
			POST(otpPath+"/validate").
			Doc("Validate OTP token").
			Reads(domain.OTPInput{}).
			Param(ws.HeaderParameter("USER-AUTH", "role used for auth").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.HeaderParameter("USER-UUID", "user unique id").DataType("string").Required(true).AllowEmptyValue(false)).
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Filter(api.BasicAuthenticate).
			Filter(api.CompressedEncodingFilter).
			To(api.ValidateOTPToken).
			Writes(domain.QueryResponse{}).
			Returns(http.StatusOK, "OK", domain.QueryResponse{}).
			Returns(http.StatusNotFound, "User Not Found", domain.ErrorResponse{}).
			Returns(http.StatusBadRequest, "Bad Request", domain.ErrorResponse{}))
	ws.Route(
		ws.
			POST(otpPath+"/disable").
			Doc("Disable OTP").
			Reads(domain.OTPInput{}).
			Param(ws.HeaderParameter("USER-AUTH", "role used for auth").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.HeaderParameter("USER-UUID", "user unique id").DataType("string").Required(true).AllowEmptyValue(false)).
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Filter(api.BasicAuthenticate).
			Filter(api.CompressedEncodingFilter).
			To(api.DisableOTP).
			Writes(domain.QueryResponse{}).
			Returns(http.StatusOK, "OK", domain.QueryResponse{}).
			Returns(http.StatusNotFound, "User Not Found", domain.ErrorResponse{}).
			Returns(http.StatusBadRequest, "Bad Request", domain.ErrorResponse{}))
	tags = []string{"apps"}
	ws.Route(
		ws.
			POST(registerPath+appPath).
			Doc("Upload app to s3").
			Param(ws.HeaderParameter("USER-AUTH", "role used for auth").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.HeaderParameter("USER-UUID", "user unique id").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("username", "owner of the apps").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("is_complex", "flag complex app split in multi source files").DataType("boolean").Required(false).AllowEmptyValue(false)).
			Param(ws.FormParameter("type", "zip archives which contain the code and description files(same name for both,description being txt,order for every app is source_code,then description)").AllowMultiple(true).
				DataType("file").Required(true).AllowMultiple(true)).
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes("multipart/form-data").
			Filter(api.BasicAuthenticate).
			Filter(api.CompressedEncodingFilter).
			To(api.UploadApp).
			Writes(domain.QueryResponse{}).
			Returns(http.StatusOK, "OK", domain.QueryResponse{}).
			Returns(http.StatusFound, "Already found", domain.ErrorResponse{}).
			Returns(http.StatusBadRequest, "Bad Request", domain.ErrorResponse{}))

	ws.Route(
		ws.
			GET(appPath).
			Doc("Retrieve apps information").
			Param(ws.HeaderParameter("USER-UUID", "user unique id").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.HeaderParameter("USER-AUTH", "role used for auth").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("appnames", "name of the apps").DataType("string").AllowEmptyValue(true).AllowMultiple(true)).
			Param(ws.QueryParameter("username", "owner of the apps").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("filter",
				"filter apps using fql filter(AND-&&,OR-||) or using simple field filtering").
				DataType("string").AllowEmptyValue(true)).
			Param(ws.QueryParameter("sort", "sort applications by name,created_timestamp or updated_timestamp").DataType("string").AllowEmptyValue(true)).
			Param(ws.QueryParameter("limit", "limit number of applications shown").DataType("integer").AllowEmptyValue(true)).
			Param(ws.QueryParameter("offset", "start index from which apps will be shown").DataType("integer").AllowEmptyValue(true)).
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Filter(api.BasicAuthenticate).
			Filter(api.CompressedEncodingFilter).
			To(api.GetAppsInfo).
			Writes(domain.GetApplicationsData{}).
			Returns(http.StatusOK, "OK", domain.GetApplicationsData{}).
			Returns(http.StatusNotFound, "App Not Found", domain.GetApplicationsData{}).
			Returns(http.StatusBadRequest, "Bad Request", domain.GetApplicationsData{}))
	ws.Route(
		ws.
			GET(appPath+aggregatesPath).
			Doc("Retrieve aggregates about applications").
			Param(ws.QueryParameter("username", "owner of the apps").DataType("string").Required(true).AllowEmptyValue(false)).
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			To(api.GetAppsAggregates).
			Writes(domain.AppsAggregatesInfo{}).
			Returns(http.StatusOK, "OK", domain.AppsAggregatesInfo{}))
	ws.Route(
		ws.
			PUT(appPath).
			Doc("Update app information").
			Reads(domain.ApplicationData{}).
			Param(ws.HeaderParameter("USER-AUTH", "role used for auth").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.HeaderParameter("USER-UUID", "user unique id").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("username", "owner of the app").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("nr_replicas", "change nr replicas of the pod(only if it is running)").DataType("integer").Required(false).AllowEmptyValue(true)).
			Param(ws.QueryParameter("max_nr_replicas", "change max nr replicas of the pod(only if it is running and for random sched)").DataType("integer").Required(false).AllowEmptyValue(true)).
			Param(ws.QueryParameter("new_image", "change current image to a new one(only if it is running)").DataType("string").Required(false).AllowEmptyValue(true)).
			Param(ws.QueryParameter("mem_usage", "set mem usage for deployment").DataType("string").Required(false).AllowEmptyValue(true)).
			Param(ws.QueryParameter("cpu_usage", "set cpu usage for deployment").DataType("string").Required(false).AllowEmptyValue(true)).
			Param(ws.QueryParameter("max_mem_usage", "set mem usage limit for deployment").DataType("string").Required(false).AllowEmptyValue(true)).
			Param(ws.QueryParameter("max_cpu_usage", "set cpu usage limit for deployment").DataType("string").Required(false).AllowEmptyValue(true)).
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Filter(api.BasicAuthenticate).
			Filter(api.CompressedEncodingFilter).
			To(api.UpdateApp).
			Writes(domain.QueryResponse{}).
			Returns(http.StatusOK, "OK", domain.QueryResponse{}).
			Returns(http.StatusNotFound, "User/Apps Not Found", domain.ErrorResponse{}).
			Returns(http.StatusBadRequest, "Bad Request", domain.ErrorResponse{}))
	ws.Route(
		ws.
			DELETE(appPath).
			Param(ws.HeaderParameter("USER-AUTH", "role used for auth").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.HeaderParameter("USER-UUID", "user unique id").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("appnames", "name of the apps you want to delete").DataType("string").Required(true).AllowEmptyValue(false).AllowMultiple(true)).
			Param(ws.QueryParameter("username", "owner of the apps").DataType("string").Required(true).AllowEmptyValue(false)).
			Doc("Deletes app").
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Filter(api.BasicAuthenticate).
			Filter(api.CompressedEncodingFilter).
			To(api.DeleteApp).
			Writes(domain.QueryResponse{}).
			Returns(http.StatusOK, "OK", domain.QueryResponse{}).
			Returns(http.StatusNotFound, "User/Apps Not Found", domain.ErrorResponse{}).
			Returns(http.StatusBadRequest, "Bad Request", domain.ErrorResponse{}))

	tags = []string{"schedule"}
	ws.Route(
		ws.
			GET(schedulePath).
			Param(ws.HeaderParameter("USER-AUTH", "role used for auth").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.HeaderParameter("USER-UUID", "user unique id").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("appnames", "name of the apps you want to schedule").DataType("string").Required(true).AllowEmptyValue(false).AllowMultiple(true)).
			Param(ws.QueryParameter("username", "owner of the apps").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("schedule_type", "type of schedulling").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("nr_replicas", "nr of replicas").DataType("integer").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("server_port", "server port for app").DataType("integer").Required(false).AllowEmptyValue(true)).
			Param(ws.QueryParameter("app_priorities", "user app priorities").DataType("string").Required(false).AllowEmptyValue(true).AllowMultiple(true)).
			Param(ws.QueryParameter("route_paths", "route paths to expose for ingress").DataType("string").Required(false).AllowEmptyValue(true).AllowMultiple(true)).
			Doc("Schedule apps").
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Filter(api.BasicAuthenticate).
			Filter(api.CompressedEncodingFilter).
			To(api.ScheduleApps).
			Writes(domain.QueryResponse{}).
			Returns(http.StatusOK, "OK", domain.QueryResponse{}).
			Returns(http.StatusNotFound, "User/Apps Not Found", domain.ErrorResponse{}).
			Returns(http.StatusBadRequest, "Bad Request", domain.ErrorResponse{}).
			Returns(http.StatusForbidden, "User not allowed", domain.ErrorResponse{}))
	ws.Route(
		ws.
			GET(getPodResultPath).
			Param(ws.HeaderParameter("USER-AUTH", "role used for auth").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.HeaderParameter("USER-UUID", "user unique id").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("app_name", "app name for which you want to get logs for").DataType("string").Required(true).AllowEmptyValue(false).AllowMultiple(false)).
			Param(ws.QueryParameter("username", "owner of the app").DataType("string").Required(true).AllowEmptyValue(false)).
			Doc("Get pod results").
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Filter(api.BasicAuthenticate).
			Filter(api.CompressedEncodingFilter).
			To(api.GetPodResults).
			Writes(domain.GetLogsFromPod{}).
			Returns(http.StatusOK, "OK", domain.GetLogsFromPod{}).
			Returns(http.StatusBadRequest, "Bad Request", domain.ErrorResponse{}).
			Returns(http.StatusNotFound, "User/Apps/Pod Not Found", domain.ErrorResponse{}))
	ws.Route(
		ws.
			GET(getPodFilePath).
			Param(ws.HeaderParameter("USER-AUTH", "role used for auth").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.HeaderParameter("USER-UUID", "user unique id").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("app_name", "app name from where you want to get file from").DataType("string").Required(true).AllowEmptyValue(false).AllowMultiple(false)).
			Param(ws.QueryParameter("username", "owner of the app").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("file_name", "name of the file you want to download").DataType("string").Required(false).AllowEmptyValue(true)).
			Doc("Download pod file").
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_OCTET).
			Filter(api.BasicAuthenticate).
			Filter(api.CompressedEncodingFilter).
			To(api.GetPodFile).
			Returns(http.StatusBadRequest, "Bad Request", domain.ErrorResponse{}).
			Returns(http.StatusNotFound, "User/Apps/Pod Not Found", domain.ErrorResponse{}))
	ws.Route(
		ws.
			POST(formSubmitPath).
			Param(ws.HeaderParameter("USER-AUTH", "role used for auth").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.HeaderParameter("USER-UUID", "user unique id").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("username", "owner of the app").DataType("string").Required(true).AllowEmptyValue(false)).
			Doc("Form submit").
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Filter(api.BasicAuthenticate).
			Filter(api.CompressedEncodingFilter).
			To(api.SubmitForm).
			Writes(domain.QueryResponse{}).
			Returns(http.StatusOK, "OK", domain.QueryResponse{}).
			Returns(http.StatusForbidden, "User not allowed", domain.ErrorResponse{}))
	ws.Route(
		ws.
			GET(formStatisticsPath).
			Doc("Form stats").
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			To(api.GetFormStats).
			Writes([]*domain.FormStatistics{}).
			Returns(http.StatusOK, "OK", []*domain.FormStatistics{}))
	ws.Route(
		ws.
			GET(grafanaDataSourcePath).
			Param(ws.QueryParameter("app_name", "name of the app to gather data from grafana").DataType("string").Required(true)).
			Param(ws.QueryParameter("grafana_format", "data format for data source").DataType("string").Required(true)).
			Param(ws.QueryParameter("grafana_from", "gather data from a specific time").DataType("string").Required(true)).
			Param(ws.QueryParameter("grafana_usage_type", "Metric to return : mem or cpu").DataType("string").Required(true)).
			Doc("Get grafana data source data for an app").
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			To(api.GetGrafanaDashboardData).
			Writes([]*domain.GrafanaDataSourceResponse{}).
			Returns(http.StatusOK, "OK", []domain.GrafanaDataSourceResponse{}).
			Returns(http.StatusBadRequest, "Bad Request", domain.ErrorResponse{}))
	ws.Route(
		ws.
			GET(grafanaAlertPath).
			Param(ws.HeaderParameter("USER-AUTH", "role used for auth").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.HeaderParameter("USER-UUID", "user unique id").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("username", "owner of the app").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("app_name", "name of the app you want to create alerts").DataType("string").Required(true)).
			Doc("Create alerts for app").
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Filter(api.BasicAuthenticate).
			Filter(api.CompressedEncodingFilter).
			To(api.CreateAppAlert).
			Writes(domain.QueryResponse{}).
			Returns(http.StatusOK, "OK", domain.QueryResponse{}).
			Returns(http.StatusNotFound, "User/App Not Found", domain.ErrorResponse{}).
			Returns(http.StatusFound, "Alert already exists", domain.ErrorResponse{}).
			Returns(http.StatusBadRequest, "Bad Request", domain.ErrorResponse{}).
			Returns(http.StatusForbidden, "User not allowed", domain.ErrorResponse{}))
	ws.Route(
		ws.
			GET(grafanaUpdateAlertPath).
			Param(ws.HeaderParameter("USER-AUTH", "role used for auth").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.HeaderParameter("USER-UUID", "user unique id").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("username", "owner of the app").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("app_name", "name of the app you want to update the alert").DataType("string").Required(true)).
			Param(ws.QueryParameter("alert_ids", "id of the alerts you want to update").DataType("string").Required(true)).
			Param(ws.QueryParameter("alert_new_mem_value", "value to update memory query").DataType("integer").Required(true)).
			Param(ws.QueryParameter("alert_new_cpu_value", "value to update cpu query").DataType("integer").Required(true)).
			Doc("Update alerts for app").
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Filter(api.BasicAuthenticate).
			Filter(api.CompressedEncodingFilter).
			To(api.UpdateAppAlert).
			Writes(domain.QueryResponse{}).
			Returns(http.StatusOK, "OK", domain.QueryResponse{}).
			Returns(http.StatusNotFound, "User/App Not Found", domain.ErrorResponse{}).
			Returns(http.StatusBadRequest, "Bad Request", domain.ErrorResponse{}).
			Returns(http.StatusForbidden, "User not allowed", domain.ErrorResponse{}))
	ws.Route(
		ws.
			DELETE(grafanaAlertPath).
			Param(ws.HeaderParameter("USER-AUTH", "role used for auth").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.HeaderParameter("USER-UUID", "user unique id").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("username", "owner of the app").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("app_name", "name of the app you want to delete the alert").DataType("string").Required(true)).
			Param(ws.QueryParameter("alert_ids", "alert ids you want to delete").DataType("string").Required(true)).
			Doc("Delete alerts for an app").
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Filter(api.BasicAuthenticate).
			Filter(api.CompressedEncodingFilter).
			To(api.DeleteAppAlert).
			Writes(domain.QueryResponse{}).
			Returns(http.StatusOK, "OK", domain.QueryResponse{}).
			Returns(http.StatusNotFound, "User/App/Alert Not Found", domain.ErrorResponse{}).
			Returns(http.StatusBadRequest, "Bad Request", domain.ErrorResponse{}).
			Returns(http.StatusForbidden, "User not allowed", domain.ErrorResponse{}))
	ws.Route(
		ws.
			GET(grafanaAlertTriggerPath).
			Param(ws.HeaderParameter("USER-AUTH", "role used for auth").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.HeaderParameter("USER-UUID", "user unique id").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("username", "owner of the app").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("app_name", "name of the app you want to get alert details").DataType("string").Required(true)).
			Doc("Get alert trigger details").
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Filter(api.BasicAuthenticate).
			Filter(api.CompressedEncodingFilter).
			To(api.GetAlertTriggerNotification).
			Writes([]domain.AlertNotification{}).
			Returns(http.StatusOK, "OK", []domain.AlertNotification{}).
			Returns(http.StatusNotFound, "User/App/Alert Not Found", domain.ErrorResponse{}).
			Returns(http.StatusBadRequest, "Bad Request", domain.ErrorResponse{}).
			Returns(http.StatusForbidden, "User not allowed", domain.ErrorResponse{}))
	//activate profiler endpoints only if it is initialized
	if api.profiler.Cpuprofile != "" {
		ws.Route(ws.GET("/profiler/start").To(api.StartProfiler))
		ws.Route(ws.GET("/profiler/stop").To(api.StopProfiler))
	}

}
