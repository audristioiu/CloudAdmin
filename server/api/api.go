package api

import (
	"cloudadmin/domain"
	"cloudadmin/repositories"
	"context"
	"net/http"

	"github.com/dgraph-io/ristretto"
	restfulspec "github.com/emicklei/go-restful-openapi/v2"
	"github.com/emicklei/go-restful/v3"
	"github.com/sirupsen/logrus"
)

const (
	registerPath = "/register"
	loginPath    = "/login"
	userPath     = "/user"
	appPath      = "/app"
)

// API represents the object used for the api, api handlers and contains context and storage + local cache
type API struct {
	ctx       context.Context
	psqlRepo  *repositories.PostgreSqlRepo
	apiCache  *ristretto.Cache
	apiLogger *logrus.Logger
}

// NewAPI returns an API object
func NewAPI(ctx context.Context, postgresRepo *repositories.PostgreSqlRepo, cache *ristretto.Cache, logger *logrus.Logger) *API {
	return &API{
		ctx:       ctx,
		psqlRepo:  postgresRepo,
		apiCache:  cache,
		apiLogger: logger,
	}
}

// todo add schedule routes

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
			Returns(http.StatusOK, "OK", "User registered succesfully").
			Returns(http.StatusFound, "Already found", domain.ErrorResponse{}).
			Returns(http.StatusBadRequest, "Bad Request", domain.ErrorResponse{}))

	ws.Route(
		ws.
			POST(loginPath).
			Doc("Login user").
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
			Doc("Retrieves user profile").
			Param(ws.PathParameter("username", "username of the account").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.HeaderParameter("Authorization", "role used for auth").DataType("string").Required(true).AllowEmptyValue(false)).
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
			Doc("Updates user profile").
			Reads(domain.UserData{}).
			Param(ws.HeaderParameter("Authorization", "role used for auth").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.HeaderParameter("USER-UUID", "user unique id").DataType("string").Required(true).AllowEmptyValue(false)).
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Filter(api.BasicAuthenticate).
			To(api.UpdateUserProfile).
			Returns(http.StatusOK, "OK", "User updated succesfully").
			Returns(http.StatusBadRequest, "Bad Request", domain.ErrorResponse{}))
	ws.Route(
		ws.
			DELETE(userPath+"/{username}").
			Doc("Deletes user").
			Param(ws.HeaderParameter("Authorization", "role used for auth").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.HeaderParameter("USER-UUID", "user unique id").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.PathParameter("username", "username of the account").DataType("string").Required(true).AllowEmptyValue(false)).
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Filter(api.AdminAuthenticate).
			To(api.DeleteUser).
			Returns(http.StatusOK, "OK", "User deleted succesfully").
			Returns(http.StatusNotFound, "User Not Found", domain.ErrorResponse{}).
			Returns(http.StatusBadRequest, "Bad Request", domain.ErrorResponse{}))

	tags = []string{"apps"}
	ws.Route(
		ws.
			POST(registerPath+appPath).
			Doc("Upload app to s3").
			Param(ws.HeaderParameter("Authorization", "role used for auth").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.HeaderParameter("USER-UUID", "user unique id").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("username", "owner of the app").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.FormParameter("type", "zip archive which contains the code and description files(same name for both,description being txt)").
				DataType("file").Required(true)).Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON, "multipart/form-data").
			Filter(api.BasicAuthenticate).
			To(api.UploadApp).
			Returns(http.StatusOK, "OK", "App registered succesfully").
			Returns(http.StatusFound, "Already found", domain.ErrorResponse{}).
			Returns(http.StatusBadRequest, "Bad Request", domain.ErrorResponse{}))

	ws.Route(
		ws.
			GET(appPath).
			Doc("Retrieves apps information by name").
			Param(ws.HeaderParameter("USER-UUID", "user unique id").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.HeaderParameter("Authorization", "role used for auth").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("appnames", "name of the apps").DataType("string").AllowEmptyValue(true).AllowMultiple(true)).
			Param(ws.QueryParameter("username", "owner of the app").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("filter",
				"filter apps by name(keyword), description(keyword), is_running, created/updated timestamp combined(?) or separate").
				DataType("string").AllowEmptyValue(true)).
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Filter(api.BasicAuthenticate).
			To(api.GetAppsInfo).
			Writes(domain.GetApplicationsData{}).
			Returns(http.StatusOK, "OK", domain.GetApplicationsData{}).
			Returns(http.StatusNotFound, "App Not Found", domain.ErrorResponse{}).
			Returns(http.StatusBadRequest, "Bad Request", domain.ErrorResponse{}))
	ws.Route(
		ws.
			PUT(appPath).
			Doc("Update app information").
			Reads(domain.ApplicationData{}).
			Param(ws.HeaderParameter("Authorization", "role used for auth").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.HeaderParameter("USER-UUID", "user unique id").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("username", "owner of the app").DataType("string").Required(true).AllowEmptyValue(false)).
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Filter(api.BasicAuthenticate).
			To(api.UpdateApp).
			Returns(http.StatusOK, "OK", "App updated succesfully").
			Returns(http.StatusBadRequest, "Bad Request", domain.ErrorResponse{}))
	ws.Route(
		ws.
			DELETE(appPath).
			Param(ws.HeaderParameter("Authorization", "role used for auth").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.HeaderParameter("USER-UUID", "user unique id").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("appname", "name of the app you want to delete").DataType("string").Required(true).AllowEmptyValue(false)).
			Param(ws.QueryParameter("username", "owner of the app").DataType("string").Required(true).AllowEmptyValue(false)).
			Doc("Deletes app").
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Filter(api.AdminAuthenticate).
			To(api.DeleteApp).
			Returns(http.StatusOK, "OK", "App deleted succesfully").
			Returns(http.StatusNotFound, "User Not Found", domain.ErrorResponse{}).
			Returns(http.StatusBadRequest, "Bad Request", domain.ErrorResponse{}).
			Returns(http.StatusForbidden, "User not allowed as admin", domain.ErrorResponse{}))

}
