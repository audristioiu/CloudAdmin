package api

import (
	"cloudadmin/domain"
	"cloudadmin/helpers"
	"net/http"
	"unicode"

	"log"

	"github.com/emicklei/go-restful/v3"
)

// UserData represents user information
type UserData struct {
	UserName     string   `json:"username"`
	Password     string   `json:"password"`
	CityAddress  string   `json:"city_address,omitempty"`
	WantNotify   string   `json:"want_notify,omitempty"`
	Applications []string `json:"applications,omitempty"`
	Role         string   `json:"role,omitempty"`
}

// ApplicationdData represents app information
type ApplicationData struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	IsRunning   string `json:"is_running"`
}

// ErrorResponse represents error info
type ErrorResponse struct {
	StatusCode int    `json:"status_code"`
	Message    string `json:"message"`
}

// AdminAuthenticate verifies that admin only can access delete endpoints
func (api *API) AdminAuthenticate(request *restful.Request, response *restful.Response, chain *restful.FilterChain) {
	errorData := domain.ErrorResponse{}
	u, p, ok := request.Request.BasicAuth()

	if !ok || u != "admin" || p != "admin" {
		log.Printf("[ERROR] User " + u + " not authorized for delete route")
		response.AddHeader("WWW-Authenticate", "Basic realm=Protected Area")
		errorData.Message = "User " + u + " is Not Authorized for delete route"
		errorData.StatusCode = http.StatusForbidden
		response.WriteEntity(errorData)
		return
	}
	chain.ProcessFilter(request, response)
}

// BasicAuthenticate verifies role and user_id for auth
func (api *API) BasicAuthenticate(request *restful.Request, response *restful.Response, chain *restful.FilterChain) {
	errorData := domain.ErrorResponse{}
	authHeader := request.HeaderParameter("Authorization")
	userIDHeader := request.HeaderParameter("USER-UUID")

	userData, err := api.psqlRepo.GetUserDataWithUUID(userIDHeader)
	if err != nil || !helpers.CheckUser(userData, authHeader) {
		log.Printf("[ERROR] User id " + userIDHeader + " not authorized")
		response.AddHeader("WWW-Authenticate", "Basic realm=Protected Area")
		errorData.Message = "User " + userIDHeader + " is Not Authorized"
		errorData.StatusCode = http.StatusForbidden
		response.WriteEntity(errorData)
		return
	}
	chain.ProcessFilter(request, response)
}

// UserRegister creates a user
func (api *API) UserRegister(request *restful.Request, response *restful.Response) {

	userData := domain.UserData{}
	errorData := domain.ErrorResponse{}
	err := request.ReadEntity(&userData)
	if err != nil {
		log.Printf("[ERROR] Couldn't read body")
		errorData.Message = "Bad Request/ could not read body"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteEntity(errorData)
		return
	}

	if userData.UserName == "" {
		log.Printf("[ERROR] Couldn't read username query parameter")
		errorData.Message = "Bad Request/ empty username"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteEntity(errorData)
		return
	}

	if len(userData.Password) < 8 {
		log.Printf("[ERROR] password too short")
		errorData.Message = "Bad Request/ Password too short"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteEntity(errorData)
		return
	}
	if !unicode.IsUpper(rune(userData.Password[0])) {
		log.Printf("[ERROR] password does not start with uppercase")
		errorData.Message = "Bad Request/ Password does not start with uppercase"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteEntity(errorData)
		return
	}
	log.Printf("%+v", userData)

	_, err = api.psqlRepo.GetUserData(userData.UserName)
	if err == nil {
		log.Printf("[ERROR] User %v already exists", userData.UserName)
		errorData.Message = "User already exists"
		errorData.StatusCode = http.StatusFound
		response.WriteEntity(errorData)
		return
	}

	err = api.psqlRepo.InsertUserData(&userData)
	if err != nil {
		errorData.Message = "Internal error/ insert in postgres"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteEntity(errorData)
		return
	}
	response.Write([]byte("User registered succesfully"))
}

// UserLogin verifies user credentials
func (api *API) UserLogin(request *restful.Request, response *restful.Response) {
	userData := domain.UserData{}
	errorData := domain.ErrorResponse{}
	err := request.ReadEntity(&userData)
	if err != nil {
		log.Printf("[ERROR] Couldn't read body")
		errorData.Message = "Bad Request/ could not read body"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteEntity(errorData)
		return
	}
	if userData.UserName == "" {
		log.Printf("[ERROR] Couldn't read username query parameter")
		errorData.Message = "Bad Request/ empty username"
		errorData.StatusCode = http.StatusBadRequest
		return
	}

	if userData.Password == "" {
		log.Printf("[ERROR] Couldn't read password query parameter")
		errorData.Message = "Bad Request/ empty password"
		errorData.StatusCode = http.StatusBadRequest
		return
	}

	dbUserData, err := api.psqlRepo.GetUserData(userData.UserName)
	if err != nil {
		log.Printf("[ERROR] User %v not found", userData.UserName)
		errorData.Message = "User not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteEntity(errorData)
		return
	}

	newUserData := helpers.GenerateRole(dbUserData)

	err = api.psqlRepo.UpdateUserRoleData(newUserData.Role, newUserData.UserID, newUserData)
	if err != nil {
		errorData.Message = "Internal error / updating in postgres"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteEntity(errorData)
		return
	}

	response.Write([]byte("User login succesfully.\nHere is your new role(use it for authorization) : " + newUserData.Role +
		"\nAnd here is your user_id(use it for authorization) : " + newUserData.UserID))
}

// GetUserProfile returns user profile based on username
func (api *API) GetUserProfile(request *restful.Request, response *restful.Response) {

	errorData := domain.ErrorResponse{}
	username := request.PathParameter("username")
	if username == "" {
		log.Printf("[ERROR] Couldn't read username query parameter")
		errorData.Message = "Bad Request/ empty username"
		errorData.StatusCode = http.StatusBadRequest
		return
	}
	userData, err := api.psqlRepo.GetUserData(username)
	if err != nil {
		log.Printf("[ERROR] User %v not found", userData.UserName)
		errorData.Message = "User not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteEntity(errorData)
		return
	}
	userData.Password = ""
	userData.Role = ""
	userData.UserID = ""
	response.WriteEntity(userData)
}

// UpdateUserProfile updates user profile
func (api *API) UpdateUserProfile(request *restful.Request, response *restful.Response) {
	userData := domain.UserData{}
	errorData := domain.ErrorResponse{}

	err := request.ReadEntity(&userData)
	if err != nil {
		log.Printf("[ERROR] Couldn't read body")
		errorData.Message = "Bad Request/ could not read body"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteEntity(errorData)
		return
	}
	log.Printf("%+v", userData)
	if userData.Role != "" || userData.UserID != "" || len(userData.Applications) > 0 {
		log.Printf("[ERROR] Wrong fields to update")
		errorData.Message = "Bad Request/ wrong fields , you can only update city_address , want_notify or password"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteEntity(errorData)
		return
	}

	err = api.psqlRepo.UpdateUserData(&userData)
	if err != nil {
		errorData.Message = "Internal error / updating in postgres"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteEntity(errorData)
		return
	}

	response.Write([]byte("User updated succesfully"))
}

// DeleteUser deletes user
func (api *API) DeleteUser(request *restful.Request, response *restful.Response) {
	errorData := domain.ErrorResponse{}
	username := request.PathParameter("username")
	if username == "" {
		log.Printf("[ERROR] Couldn't read username query parameter")
		errorData.Message = "Bad Request/ empty username"
		errorData.StatusCode = http.StatusBadRequest
		return
	}
	err := api.psqlRepo.DeleteUserData(username)
	if err != nil {
		log.Printf("[ERROR] User %v not found", username)
		errorData.Message = "User not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteEntity(errorData)
		return
	}

	response.Write([]byte("User deleted succesfully"))
}

// UploadApp uploads app to s3
func (api *API) UploadApp(request *restful.Request, response *restful.Response) {

	appData := domain.ApplicationData{}
	errorData := domain.ErrorResponse{}
	err := request.ReadEntity(&appData)
	if err != nil {
		log.Printf("[ERROR] Couldn't read body")
		errorData.Message = "Bad Request/ could not read body"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteEntity(errorData)
		return
	}

	username := request.QueryParameter("username")
	if username == "" {
		log.Printf("[ERROR] Couldn't read username query parameter")
		errorData.Message = "Bad Request/ empty username"
		errorData.StatusCode = http.StatusBadRequest
		return
	}

	_, err = api.psqlRepo.GetAppData(appData.Name)
	if err == nil {
		log.Printf("[ERROR] App %v already exists", appData.Name)
		errorData.Message = "App already exists"
		errorData.StatusCode = http.StatusFound
		response.WriteEntity(errorData)
		return
	}

	err = api.psqlRepo.InsertAppData(&appData)
	if err != nil {
		errorData.Message = "Internal error/ insert in postgres"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteEntity(errorData)
		return
	}

	err = api.psqlRepo.UpdateUserAppsData(appData.Name, username)
	if err != nil {
		errorData.Message = "Internal error/ update users in postgres"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteEntity(errorData)
		return
	}
	//app pus in s3 + insert in tabela + aplicatie atasata la user

	response.Write([]byte("App uploaded succesfully"))
}

// GetAppInfo retrieves app information
func (api *API) GetAppInfo(request *restful.Request, response *restful.Response) {

	errorData := domain.ErrorResponse{}
	appname := request.QueryParameter("appname")
	if appname == "" {
		log.Printf("[ERROR] Couldn't read appname query parameter")
		errorData.Message = "Bad Request/ empty appname"
		errorData.StatusCode = http.StatusBadRequest
		return
	}

	username := request.QueryParameter("username")
	if username == "" {
		log.Printf("[ERROR] Couldn't read username query parameter")
		errorData.Message = "Bad Request/ empty username"
		errorData.StatusCode = http.StatusBadRequest
		return
	}

	appData, err := api.psqlRepo.GetAppData(appname)
	if err != nil {
		log.Printf("[ERROR] App %v not found", appname)
		errorData.Message = "App not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteEntity(errorData)
		return
	}

	userUUID := request.HeaderParameter("USER-UUID")
	userData, err := api.psqlRepo.GetUserDataWithUUID(userUUID)
	if err != nil {
		log.Printf("[ERROR] User id" + userUUID + " not authorized")
		response.AddHeader("WWW-Authenticate", "Basic realm=Protected Area")
		errorData.Message = "User " + userUUID + " is Not Authorized"
		errorData.StatusCode = http.StatusForbidden
		response.WriteEntity(errorData)
		return
	}

	flag := true
	for _, app := range userData.Applications {
		if app == appname {
			flag = false
			break
		}
	}

	userData.UserName = username

	if helpers.CheckUser(userData, userData.Role) {
		flag = true
	}
	if !flag {
		log.Printf("[ERROR] User" + username + " not authorized")
		response.AddHeader("WWW-Authenticate", "Basic realm=Protected Area")
		errorData.Message = "User " + username + " is Not Authorized"
		errorData.StatusCode = http.StatusForbidden
		response.WriteEntity(errorData)
		return
	}
	response.WriteEntity(appData)
}

// UpdateApp updates app info
func (api *API) UpdateApp(request *restful.Request, response *restful.Response) {

	appData := domain.ApplicationData{}
	errorData := domain.ErrorResponse{}

	err := request.ReadEntity(&appData)
	if err != nil {
		log.Printf("[ERROR] Couldn't read body")
		errorData.Message = "Bad Request/ could not read body"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteEntity(errorData)
		return
	}
	log.Printf("%+v", appData)

	err = api.psqlRepo.UpdateAppData(&appData)
	if err != nil {
		errorData.Message = "Internal error / updating in postgres"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteEntity(errorData)
		return
	}

	response.Write([]byte("App updated succesfully"))
}

// DeleteApp deletes app
func (api *API) DeleteApp(request *restful.Request, response *restful.Response) {

	errorData := domain.ErrorResponse{}

	appname := request.QueryParameter("appname")
	if appname == "" {
		log.Printf("[ERROR] Couldn't read appname query parameter")
		errorData.Message = "Bad Request/ empty appname"
		errorData.StatusCode = http.StatusBadRequest
		return
	}

	username := request.QueryParameter("username")
	if username == "" {
		log.Printf("[ERROR] Couldn't read username query parameter")
		errorData.Message = "Bad Request/ empty username"
		errorData.StatusCode = http.StatusBadRequest
		return
	}

	err := api.psqlRepo.DeleteAppData(appname, username)
	if err != nil {
		log.Printf("[ERROR] App %v not found", appname)
		errorData.Message = "App not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteEntity(errorData)
		return
	}

	response.Write([]byte("App deleted succesfully"))
}
