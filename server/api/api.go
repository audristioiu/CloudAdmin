package api

import (
	"cloudadmin/repositories"
	"context"
	"net/http"

	restfulspec "github.com/emicklei/go-restful-openapi/v2"
	"github.com/emicklei/go-restful/v3"
)

const (
	registerPath = "/register"
	loginPath    = "/login"
	userPath     = "/user"
	appPath      = "/app"
)

// API represents the object used for the api, api handlers and contains context and storage
type API struct {
	ctx      context.Context
	psqlRepo *repositories.PostgreSqlRepo
}

// NewAPI returns an API object
func NewAPI(ctx context.Context, psqlRepo *repositories.PostgreSqlRepo) *API {
	return &API{
		ctx:      ctx,
		psqlRepo: psqlRepo,
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
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			To(api.UserRegister).
			Writes(UserData{}).
			Returns(http.StatusOK, "OK", "User registered succesfully").
			Returns(http.StatusFound, "Already found", ErrorResponse{}).
			Returns(http.StatusBadRequest, "Bad Request", ErrorResponse{}))

	ws.Route(
		ws.
			POST(loginPath).
			Doc("Login user").
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			To(api.UserLogin).
			Writes(UserData{}).
			Returns(http.StatusOK, "OK", "User login succesfully").
			Returns(http.StatusNotFound, "User Not Found", ErrorResponse{}).
			Returns(http.StatusBadRequest, "Bad Request", ErrorResponse{}))
	ws.Route(
		ws.
			GET(userPath+"/{username}").
			Param(ws.PathParameter("username", "username of the account").DataType("string").AllowEmptyValue(false)).
			Param(ws.HeaderParameter("Authorization", "role used for auth").DataType("string").AllowEmptyValue(false)).
			Param(ws.HeaderParameter("USER-UUID", "user unique id").DataType("string").AllowEmptyValue(false)).
			Doc("Retrieves user profile").
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Filter(api.BasicAuthenticate).
			To(api.GetUserProfile).
			Writes(UserData{}).
			Returns(http.StatusOK, "OK", UserData{}).
			Returns(http.StatusNotFound, "User Not Found", ErrorResponse{}).
			Returns(http.StatusBadRequest, "Bad Request", ErrorResponse{}))
	ws.Route(
		ws.
			PUT(userPath).
			Doc("Updates user profile").
			Param(ws.HeaderParameter("Authorization", "role used for auth").DataType("string").AllowEmptyValue(false)).
			Param(ws.HeaderParameter("USER-UUID", "user unique id").DataType("string").AllowEmptyValue(false)).
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Filter(api.BasicAuthenticate).
			To(api.UpdateUserProfile).
			Returns(http.StatusOK, "OK", "User updated succesfully").
			Returns(http.StatusBadRequest, "Bad Request", ErrorResponse{}))
	ws.Route(
		ws.
			DELETE(userPath+"/{username}").
			Param(ws.PathParameter("username", "username of the account").DataType("string").AllowEmptyValue(false)).
			Doc("Deletes user").
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Filter(api.AdminAuthenticate).
			To(api.DeleteUser).
			Returns(http.StatusOK, "OK", "User deleted succesfully").
			Returns(http.StatusNotFound, "User Not Found", ErrorResponse{}).
			Returns(http.StatusBadRequest, "Bad Request", ErrorResponse{}))

	ws.Route(
		ws.
			POST(registerPath+appPath).
			Doc("Upload app to s3").
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Param(ws.QueryParameter("username", "owner of the app").DataType("string").AllowEmptyValue(false)).
			Param(ws.HeaderParameter("Authorization", "role used for auth").DataType("string").AllowEmptyValue(false)).
			Param(ws.HeaderParameter("USER-UUID", "user unique id").DataType("string").AllowEmptyValue(false)).
			Filter(api.BasicAuthenticate).
			To(api.UploadApp).
			Writes(ApplicationData{}).
			Returns(http.StatusOK, "OK", "App registered succesfully").
			Returns(http.StatusFound, "Already found", ErrorResponse{}).
			Returns(http.StatusBadRequest, "Bad Request", ErrorResponse{}))

	ws.Route(
		ws.
			GET(appPath).
			Param(ws.QueryParameter("appname", "name of the app").DataType("string").AllowEmptyValue(false)).
			Param(ws.QueryParameter("username", "owner of the app").DataType("string").AllowEmptyValue(false)).
			Param(ws.HeaderParameter("Authorization", "role used for auth").DataType("string").AllowEmptyValue(false)).
			Param(ws.HeaderParameter("USER-UUID", "user unique id").DataType("string").AllowEmptyValue(false)).
			Doc("Retrieves app information").
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Filter(api.BasicAuthenticate).
			To(api.GetAppInfo).
			Writes(ApplicationData{}).
			Returns(http.StatusOK, "OK", ApplicationData{}).
			Returns(http.StatusNotFound, "App Not Found", ErrorResponse{}).
			Returns(http.StatusBadRequest, "Bad Request", ErrorResponse{}))
	ws.Route(
		ws.
			PUT(appPath).
			Doc("Update app information").
			Param(ws.HeaderParameter("Authorization", "role used for auth").DataType("string").AllowEmptyValue(false)).
			Param(ws.HeaderParameter("USER-UUID", "user unique id").DataType("string").AllowEmptyValue(false)).
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Filter(api.BasicAuthenticate).
			To(api.UpdateApp).
			Returns(http.StatusOK, "OK", "App updated succesfully").
			Returns(http.StatusBadRequest, "Bad Request", ErrorResponse{}))
	ws.Route(
		ws.
			DELETE(appPath).
			Param(ws.QueryParameter("appname", "name of the app you want to delete").DataType("string").AllowEmptyValue(false)).
			Param(ws.QueryParameter("username", "owner of the app").DataType("string").AllowEmptyValue(false)).
			Doc("Deletes app").
			Metadata(restfulspec.KeyOpenAPITags, tags).
			Produces(restful.MIME_JSON).
			Consumes(restful.MIME_JSON).
			Filter(api.AdminAuthenticate).
			To(api.DeleteApp).
			Returns(http.StatusOK, "OK", "App deleted succesfully").
			Returns(http.StatusNotFound, "User Not Found", ErrorResponse{}).
			Returns(http.StatusBadRequest, "Bad Request", ErrorResponse{}))

}
