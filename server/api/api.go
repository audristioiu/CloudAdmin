package api

import (
	"cloudadmin/clients"
	"cloudadmin/domain"
	"cloudadmin/repositories"
	"context"
	"net"
	"net/http"

	"github.com/dgraph-io/ristretto"
	restfulspec "github.com/emicklei/go-restful-openapi/v2"
	"github.com/emicklei/go-restful/v3"
	"go.uber.org/zap"
)

const (
	registerPath     = "/register"
	loginPath        = "/login"
	userPath         = "/user"
	appPath          = "/app"
	aggregatesPath   = "/aggregates"
	schedulePath     = "/schedule"
	getPodResultPath = "/getresults"
)

// API represents the object used for the api, api handlers and contains context and storage + local cache + profiling service + clients
type API struct {
	ctx          context.Context
	psqlRepo     *repositories.PostgreSqlRepo
	apiCache     *ristretto.Cache
	apiLogger    *zap.Logger
	profiler     *repositories.ProfilingService
	dockerClient *clients.DockerClient
	kubeClient   *clients.KubernetesClient
	graphiteAddr *net.TCPAddr
}

// NewAPI returns an API object
func NewAPI(ctx context.Context, postgresRepo *repositories.PostgreSqlRepo, cache *ristretto.Cache, logger *zap.Logger,
	cpuProfiler *repositories.ProfilingService, dockerClient *clients.DockerClient, kubeClient *clients.KubernetesClient,
	graphiteAddr *net.TCPAddr) *API {
	return &API{
		ctx:          ctx,
		psqlRepo:     postgresRepo,
		apiCache:     cache,
		apiLogger:    logger,
		profiler:     cpuProfiler,
		dockerClient: dockerClient,
		kubeClient:   kubeClient,
		graphiteAddr: graphiteAddr,
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
			Param(ws.QueryParameter("username", "username of the account").DataType("string").Required(true).AllowEmptyValue(false).AllowMultiple(true)).
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Filter(api.AdminAuthenticate).
			To(api.DeleteUser).
			Returns(http.StatusOK, "OK", domain.QueryResponse{}).
			Returns(http.StatusNotFound, "User Not Found", domain.ErrorResponse{}).
			Returns(http.StatusBadRequest, "Bad Request", domain.ErrorResponse{}).
			Returns(http.StatusForbidden, "User not allowed as admin", domain.ErrorResponse{}))

	tags = []string{"apps"}
	ws.Route(
		ws.
			POST(registerPath+appPath).
			Doc("Upload app to s3").
			Param(ws.HeaderParameter("USER-AUTH", "role used for auth").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.HeaderParameter("USER-UUID", "user unique id").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("username", "owner of the apps").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("is_complex", "flag complex app split in multi source files").DataType("boolean").Required(false).AllowEmptyValue(false)).
			Param(ws.FormParameter("type", "zip archive which contains the code and description files(same name for both,description being txt,order for every app is source_code,then description)").AllowMultiple(true).
				DataType("file").Required(true).AllowMultiple(true)).
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes("multipart/form-data").
			Filter(api.BasicAuthenticate).
			To(api.UploadApp).
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
				"filter apps by name(keyword), description(keyword), is_running, created/updated timestamp combined(AND-&&,OR-||) or separate").
				DataType("string").AllowEmptyValue(true)).
			Param(ws.QueryParameter("sort", "sort applications by name,created_timestamp or updated_timestamp").DataType("string").AllowEmptyValue(true)).
			Param(ws.QueryParameter("limit", "limit number of applications shown").DataType("integer").AllowEmptyValue(true)).
			Param(ws.QueryParameter("offset", "start index from which apps will be shown").DataType("integer").AllowEmptyValue(true)).
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Filter(api.BasicAuthenticate).
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
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Filter(api.BasicAuthenticate).
			To(api.UpdateApp).
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
			Filter(api.AdminAuthenticate).
			To(api.DeleteApp).
			Returns(http.StatusOK, "OK", domain.QueryResponse{}).
			Returns(http.StatusNotFound, "User/Apps Not Found", domain.ErrorResponse{}).
			Returns(http.StatusBadRequest, "Bad Request", domain.ErrorResponse{}).
			Returns(http.StatusForbidden, "User not allowed as admin", domain.ErrorResponse{}))

	tags = []string{"schedule"}
	ws.Route(
		ws.
			GET(schedulePath).
			Param(ws.HeaderParameter("USER-AUTH", "role used for auth").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.HeaderParameter("USER-UUID", "user unique id").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("appnames", "name of the apps you want to delete").DataType("string").Required(true).AllowEmptyValue(false).AllowMultiple(true)).
			Param(ws.QueryParameter("username", "owner of the apps").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("schedule_type", "type of schedulling").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("nr_replicas", "nr of replicas(only for normal schedulling)").DataType("int32").Required(true).AllowEmptyValue(false)).
			Doc("Schedule apps").
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Filter(api.BasicAuthenticate).
			To(api.ScheduleApps).
			Returns(http.StatusOK, "OK", domain.QueryResponse{}).
			Returns(http.StatusNotFound, "User/Apps Not Found", domain.ErrorResponse{}).
			Returns(http.StatusBadRequest, "Bad Request", domain.ErrorResponse{}).
			Returns(http.StatusForbidden, "User not allowed", domain.ErrorResponse{}))
	ws.Route(
		ws.
			GET(getPodResultPath).
			Param(ws.HeaderParameter("USER-AUTH", "role used for auth").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.HeaderParameter("USER-UUID", "user unique id").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("pod_name", "pod name for which you want to get logs for").DataType("string").Required(true).AllowEmptyValue(false).AllowMultiple(false)).
			Param(ws.QueryParameter("username", "owner of the app").DataType("string").Required(true).AllowEmptyValue(false)).
			Doc("Get pod results").
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Filter(api.BasicAuthenticate).
			To(api.GetPodResults).
			Returns(http.StatusOK, "OK", domain.GetLogsFromPod{}).
			Returns(http.StatusBadRequest, "Bad Request", domain.ErrorResponse{}).
			Returns(http.StatusNotFound, "User/Apps/Pod Not Found", domain.ErrorResponse{}))

	//activate profiler endpoints only if it is initialized
	if api.profiler.Cpuprofile != "" {
		ws.Route(ws.GET("/profiler/start").To(api.StartProfiler))
		ws.Route(ws.GET("/profiler/stop").To(api.StopProfiler))
	}

}
