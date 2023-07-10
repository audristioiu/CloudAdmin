package api

import (
	"archive/zip"
	"cloudadmin/domain"
	"cloudadmin/helpers"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/emicklei/go-restful/v3"
)

// AdminAuthenticate verifies role and user_id for admin
func (api *API) AdminAuthenticate(request *restful.Request, response *restful.Response, chain *restful.FilterChain) {
	errorData := domain.ErrorResponse{}
	authHeader := request.HeaderParameter("Authorization")
	userIDHeader := request.HeaderParameter("USER-UUID")

	userData, err := api.psqlRepo.GetUserDataWithUUID(userIDHeader)
	if err != nil || !helpers.CheckUser(userData, authHeader) || userData.UserName != "admin" {
		api.apiLogger.Printf("[ERROR] User id " + userIDHeader + " not authorized")
		response.AddHeader("WWW-Authenticate", "Basic realm=Protected Area")
		errorData.Message = "User " + userIDHeader + " is Not Authorized"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
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
		api.apiLogger.Printf("[ERROR] User id " + userIDHeader + " not authorized")
		response.AddHeader("WWW-Authenticate", "Basic realm=Protected Area")
		errorData.Message = "User " + userIDHeader + " is Not Authorized"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
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
		api.apiLogger.Printf("[ERROR] Couldn't read body with error : %+v", err)
		errorData.Message = "Bad Request/ could not read body"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	if userData.UserName == "" {
		api.apiLogger.Printf("[ERROR] Couldn't read username query parameter")
		errorData.Message = "Bad Request/ empty username"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	if len(userData.Password) < 8 {
		api.apiLogger.Printf("[ERROR] password too short")
		errorData.Message = "Bad Request/ Password too short"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	if !unicode.IsUpper(rune(userData.Password[0])) {
		api.apiLogger.Printf("[ERROR] password does not start with uppercase")
		errorData.Message = "Bad Request/ Password does not start with uppercase"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	userRetrievedData, _ := api.psqlRepo.GetUserData(userData.UserName)
	if userRetrievedData != nil {
		api.apiLogger.Printf("[ERROR] User %v already exists", userData.UserName)
		errorData.Message = "User already exists"
		errorData.StatusCode = http.StatusFound
		response.WriteHeader(http.StatusFound)
		response.WriteEntity(errorData)
		return
	}

	nowTime := time.Now()
	userData.JoinedDate = nowTime
	userData.LastTimeOnline = nowTime
	userData.Applications = []string{}

	err = api.psqlRepo.InsertUserData(&userData)
	if err != nil {
		errorData.Message = "Internal error/ insert user data in postgres"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}
	response.Write([]byte("User registered succesfully"))
}

// UserLogin verifies user credentials
func (api *API) UserLogin(request *restful.Request, response *restful.Response) {
	userData := domain.UserData{}
	newUserData := &domain.UserData{}

	errorData := domain.ErrorResponse{}
	err := request.ReadEntity(&userData)
	if err != nil {
		api.apiLogger.Printf("[ERROR] Couldn't read body with error : %+v", err)
		errorData.Message = "Bad Request/ could not read body"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	if userData.UserName == "" {
		api.apiLogger.Printf("[ERROR] Couldn't read username query parameter")
		errorData.Message = "Bad Request/ empty username"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	if userData.UserName == "admin" || strings.Contains(userData.UserName, "admin") {
		api.apiLogger.Printf("[ERROR] You are not allowed to login as admin")
		errorData.Message = "Status forbidden/  You are not allowed to login as admin"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
		response.WriteEntity(errorData)
		return
	}

	if userData.Password == "" {
		api.apiLogger.Printf("[ERROR] Couldn't read password query parameter")
		errorData.Message = "Bad Request/ empty password"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	if len(userData.Password) < 8 {
		api.apiLogger.Printf("[ERROR] password too short")
		errorData.Message = "Bad Request/ Password too short"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	if !unicode.IsUpper(rune(userData.Password[0])) {
		api.apiLogger.Printf("[ERROR] password does not start with uppercase")
		errorData.Message = "Bad Request/ Password does not start with uppercase"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	dbUserData, err := api.psqlRepo.GetUserData(userData.UserName)
	if err != nil {
		api.apiLogger.Printf("[ERROR] User %v not found", userData.UserName)
		errorData.Message = "User not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteHeader(http.StatusNotFound)
		response.WriteEntity(errorData)
		return
	}

	if !helpers.CheckPasswordHash(userData.Password, dbUserData.Password) {
		api.apiLogger.Printf("[ERROR] Wrong password given. Please try again.")
		errorData.Message = "Wrong Password"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	if dbUserData.Role == "" {
		newUserData = helpers.GenerateRole(dbUserData)
		err = api.psqlRepo.UpdateUserRoleData(newUserData.Role, newUserData.UserID, newUserData)
		if err != nil {
			errorData.Message = "Internal error / updating role in postgres"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return
		}
	} else {
		newUserData = dbUserData
	}

	nowTime := time.Now()
	newUserData.LastTimeOnline = nowTime

	err = api.psqlRepo.UpdateUserLastTimeOnlineData(newUserData.LastTimeOnline, newUserData)
	if err != nil {
		errorData.Message = "Internal error / updating last_time in postgres"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}

	newUserData.Password = ""

	response.WriteEntity(newUserData)
}

// GetUserProfile returns user profile based on username
func (api *API) GetUserProfile(request *restful.Request, response *restful.Response) {

	errorData := domain.ErrorResponse{}

	//calculate key and use cache to get the response
	marshalledRequest, err := json.Marshal(request.Request.URL)
	if err != nil {
		api.apiLogger.Printf("[ERROR] Couldn't marshal request %v", request.Request.URL)
		errorData.Message = "Internal server error/Cannot marshal marshalledRequest in User Profile"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}
	userDataCache, err := api.apiCache.Get(marshalledRequest)
	if err != nil {

		username := request.PathParameter("username")
		if username == "" {
			api.apiLogger.Printf("[ERROR] Couldn't read username path parameter")
			errorData.Message = "Bad Request/ empty username"
			errorData.StatusCode = http.StatusBadRequest
			response.WriteHeader(http.StatusBadRequest)
			response.WriteEntity(errorData)
			return
		}

		userData, err := api.psqlRepo.GetUserData(username)
		if err != nil {
			api.apiLogger.Printf("[ERROR] User %v not found", userData.UserName)
			errorData.Message = "User not found"
			errorData.StatusCode = http.StatusNotFound
			response.WriteHeader(http.StatusNotFound)
			response.WriteEntity(errorData)
			return
		}
		api.apiLogger.Printf("[DEBUG] Not found in cache %v", username)
		userData.Password = ""
		userData.Role = ""
		userData.UserID = ""
		response.WriteEntity(userData)
		marshalledUserData, err := json.Marshal(userData)
		if err != nil {
			api.apiLogger.Printf("[ERROR] Couldn't unmarshal request %v", userData)
			errorData.Message = "Internal server error/Cannot unmarshal user data cache"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return

		}
		// If not in cache, set it
		api.apiCache.Set(marshalledRequest, marshalledUserData, 300)
	} else {

		userData := domain.UserData{}
		err = json.Unmarshal(userDataCache, &userData)
		if err != nil {
			api.apiLogger.Printf("[ERROR] Couldn't unmarshal user_data %v", string(userDataCache))
			errorData.Message = "Internal server error/Cannot unmarshal user data from cache"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
		}

		api.apiLogger.Printf("[INFO] Found in cache %v", userData.UserName)

		userData.Password = ""
		userData.Role = ""
		userData.UserID = ""
		response.WriteEntity(userData)
	}

}

// UpdateUserProfile updates user profile
func (api *API) UpdateUserProfile(request *restful.Request, response *restful.Response) {
	userData := domain.UserData{}
	errorData := domain.ErrorResponse{}

	err := request.ReadEntity(&userData)
	if err != nil {
		api.apiLogger.Printf("[ERROR] Couldn't read body with error : %+v", err)
		errorData.Message = "Bad Request/ could not read body"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	if userData.Role != "" || userData.UserID != "" || len(userData.Applications) > 0 {
		api.apiLogger.Printf("[ERROR] Wrong fields to update")
		errorData.Message = "Bad Request/ wrong fields , you can only update city_address ,email,  want_notify or password"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	if userData.Password != "" {
		if len(userData.Password) < 8 {
			api.apiLogger.Printf("[ERROR] password too short")
			errorData.Message = "Bad Request/ Password too short"
			errorData.StatusCode = http.StatusBadRequest
			response.WriteHeader(http.StatusBadRequest)
			response.WriteEntity(errorData)
			return
		}
		if !unicode.IsUpper(rune(userData.Password[0])) {
			api.apiLogger.Printf("[ERROR] password does not start with uppercase")
			errorData.Message = "Bad Request/ Password does not start with uppercase"
			errorData.StatusCode = http.StatusBadRequest
			response.WriteHeader(http.StatusBadRequest)
			response.WriteEntity(errorData)
			return
		}
	}

	err = api.psqlRepo.UpdateUserData(&userData)
	if err != nil {
		errorData.Message = "Internal error / updating user data in postgres"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
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
		api.apiLogger.Printf("[ERROR] Couldn't read username query parameter")
		errorData.Message = "Bad Request/ empty username"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}
	err := api.psqlRepo.DeleteUserData(username)
	if err != nil {
		api.apiLogger.Printf("[ERROR] User %v not found", username)
		errorData.Message = "User not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteHeader(http.StatusNotFound)
		response.WriteEntity(errorData)
		return
	}

	response.Write([]byte("User deleted succesfully"))
}

// UploadApp uploads app to s3
func (api *API) UploadApp(request *restful.Request, response *restful.Response) {

	errorData := domain.ErrorResponse{}

	userIDHeader := request.HeaderParameter("USER-UUID")

	username := request.QueryParameter("username")
	if username == "" {
		api.apiLogger.Printf("[ERROR] Couldn't read username query parameter")
		errorData.Message = "Bad Request/ empty username"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	userData, err := api.psqlRepo.GetUserDataWithUUID(userIDHeader)
	if err != nil {
		api.apiLogger.Printf("[ERROR] User id" + userIDHeader + " not authorized")
		response.AddHeader("WWW-Authenticate", "Basic realm=Protected Area")
		errorData.Message = "User " + userIDHeader + " is Not Authorized"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
		response.WriteEntity(errorData)
		return
	}

	flag := true

	userData.UserName = username

	if !helpers.CheckUser(userData, userData.Role) {
		flag = false
	}
	if !flag {
		api.apiLogger.Printf("[ERROR] User" + username + " not authorized")
		response.AddHeader("WWW-Authenticate", "Basic realm=Protected Area")
		errorData.Message = "User " + username + " is Not Authorized"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
		response.WriteEntity(errorData)
		return

	}

	file, handler, err := request.Request.FormFile("file")
	if err != nil {
		api.apiLogger.Printf("[ERROR] Couldn't form file with error : %+v", err)
		errorData.Message = "Internal error/ could not form file"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}

	// Create a new file in the uploads directory
	f, err := os.OpenFile(handler.Filename, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		api.apiLogger.Printf("[ERROR] Couldn't open file")
		errorData.Message = "Internal error/ could not open file"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}

	// Copy the contents of the file to the new file
	_, err = io.Copy(f, file)
	if err != nil {
		api.apiLogger.Printf("[ERROR] Couldn't copy file with error : %+v", err)
		errorData.Message = "Internal error/ could not copy file"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}

	r, err := zip.OpenReader(handler.Filename)
	if err != nil {
		api.apiLogger.Printf("[ERROR] Couldn't open zipReader with error : %+v", err)
		errorData.Message = "Internal error/ could not open zipReader"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
	}

	// Iterate through the files in the archive,
	// printing some of their contents.
	for i, f := range r.File {

		appData := domain.ApplicationData{}

		nowTime := time.Now()
		appData.CreatedTimestamp = nowTime
		appData.UpdatedTimestamp = nowTime

		api.apiLogger.Printf("Writting information for file %v:\n", f.Name)
		rc, err := f.Open()
		if err != nil {
			api.apiLogger.Fatal(err)
		}
		descr, err1 := io.ReadAll(rc)
		if err1 != nil {
			api.apiLogger.Printf("[ERROR] Couldn't read io.Reader with error : %+v", err1)
			errorData.Message = "Internal Error/  Couldn't read io.Reader"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return
		}
		defer rc.Close()
		if strings.Contains(f.Name, ".txt") {
			if i%2 == 0 {
				appData.Name = r.File[i+1].Name
			} else {
				appData.Name = r.File[i-1].Name
			}

			appData.Description = string(descr)

			appData.IsRunning = "false"
			appsRetrievedData, err := api.psqlRepo.GetAppsData(appData.Name, "")

			if err != nil {
				errorData.Message = "Internal error / get app in postgres"
				errorData.StatusCode = http.StatusInternalServerError
				response.WriteHeader(http.StatusInternalServerError)
				response.WriteEntity(errorData)
				return
			}
			if len(appsRetrievedData) != 0 {
				api.apiLogger.Printf("[ERROR] App %v already exists", appData.Name)
				errorData.Message = "App already exists"
				errorData.StatusCode = http.StatusFound
				response.WriteHeader(http.StatusFound)
				response.WriteEntity(errorData)
				return
			}

			err = api.psqlRepo.InsertAppData(&appData)
			if err != nil {
				errorData.Message = "Internal error/ insert app data in postgres"
				errorData.StatusCode = http.StatusInternalServerError
				response.WriteHeader(http.StatusInternalServerError)
				response.WriteEntity(errorData)
				return
			}

			err = api.psqlRepo.UpdateUserAppsData(appData.Name, username)
			if err != nil {
				errorData.Message = "Internal error/ update user apps in postgres"
				errorData.StatusCode = http.StatusInternalServerError
				response.WriteHeader(http.StatusInternalServerError)
				response.WriteEntity(errorData)
				return
			}
		} else {
			//upload in s3
			api.apiLogger.Println("upload s3")
			api.apiLogger.Println(string(descr))

		}

	}

	//Close handlers and delete temp files
	file.Close()
	f.Close()
	r.Close()
	os.Remove(handler.Filename)
	response.Write([]byte("App uploaded succesfully"))
}

// GetAppsInfo retrieves apps information
func (api *API) GetAppsInfo(request *restful.Request, response *restful.Response) {

	errorData := domain.ErrorResponse{}

	userIDHeader := request.HeaderParameter("USER-UUID")
	authHeader := request.HeaderParameter("Authorization")

	//Calculate key and use cache to get the response
	marshalledRequest, err := json.Marshal(request.Request.URL)
	if err != nil {
		api.apiLogger.Printf("[ERROR] Couldn't marshal request %v", request.Request.URL)
		errorData.Message = "Internal server error/Cannot marshal"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
		response.WriteEntity(errorData)
		return
	}

	appsDataCache, err := api.apiCache.Get(marshalledRequest)

	if err != nil {
		var appNamesList []string
		var filter string

		appnames := request.QueryParameter("appnames")

		username := request.QueryParameter("username")
		if username == "" {
			api.apiLogger.Printf("[ERROR] Couldn't read username query parameter")
			errorData.Message = "Bad Request/ empty username"
			errorData.StatusCode = http.StatusBadRequest
			response.WriteHeader(http.StatusBadRequest)
			response.WriteEntity(errorData)
			return
		}
		api.apiLogger.Printf("[DEBUG] Apps not found in cache for user %v", username)

		userData, err := api.psqlRepo.GetUserDataWithUUID(userIDHeader)
		if err != nil || !helpers.CheckUser(userData, authHeader) {
			api.apiLogger.Printf("[ERROR] User id " + userIDHeader + " not authorized")
			response.AddHeader("WWW-Authenticate", "Basic realm=Protected Area")
			errorData.Message = "User " + userIDHeader + " is Not Authorized"
			errorData.StatusCode = http.StatusForbidden
			response.WriteHeader(http.StatusForbidden)
			response.WriteEntity(errorData)
			return
		}

		// Check filter to contain : and to have both type and value
		filter = request.QueryParameter("filter")
		if filter != "" {
			if !strings.Contains(filter, ":") || strings.Split(filter, ":")[1] == "" {
				api.apiLogger.Printf("[ERROR] Invalid filter")
				errorData.Message = "Bad Request / Invalid filter"
				errorData.StatusCode = http.StatusBadRequest
				response.WriteHeader(http.StatusBadRequest)
				response.WriteEntity(errorData)
				return
			}

		}

		if appnames == "" {
			appNamesList = userData.Applications
		} else {
			appNamesList = strings.Split(appnames, ",")
		}

		var appsInfo domain.GetApplicationsData
		appsInfo.Response = make([]*domain.ApplicationData, 0)
		appsInfo.Errors = make([]domain.ErrorResponse, 0)
		for _, appName := range appNamesList {
			appsData, err := api.psqlRepo.GetAppsData(strings.TrimSpace(appName), filter)
			if err != nil {
				api.apiLogger.Printf("[ERROR] App %v not found", appName)
				errorData.Message = "App " + appName + " not found"
				errorData.StatusCode = http.StatusNotFound
				appsInfo.Errors = append(appsInfo.Errors, errorData)
				continue
			}
			if len(appsData) == 0 {
				api.apiLogger.Printf("[INFO] No apps found")

				errorData.Message = "App " + appName + " not found"
				errorData.StatusCode = http.StatusNotFound
				appsInfo.Errors = append(appsInfo.Errors, errorData)
				continue
			}
			appsInfo.Response = append(appsInfo.Response, appsData...)

		}
		if len(appsInfo.Response) > 1 {
			appsInfo = helpers.Unique(appsInfo)
		}

		if !helpers.CheckAppsExist(userData.Applications, appsInfo.Response) {
			api.apiLogger.Printf("[ERROR] User " + username + " not authorized")
			response.AddHeader("WWW-Authenticate", "Basic realm=Protected Area")
			errorData.Message = "User " + username + " is Not Authorized"
			errorData.StatusCode = http.StatusForbidden
			response.WriteHeader(http.StatusForbidden)
			response.WriteEntity(errorData)
			return
		}

		response.WriteEntity(appsInfo)
		marshalledAppsInfo, err := json.Marshal(appsInfo)
		if err != nil {
			api.apiLogger.Printf("[ERROR] Couldn't marshal apps %v", appsInfo)
			errorData.Message = "Internal server error/Cannot marshal apps info"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return
		}

		//If not in cache, set it
		api.apiCache.Set(marshalledRequest, marshalledAppsInfo, 300)
		return
	} else {
		appsData := domain.GetApplicationsData{}
		err = json.Unmarshal(appsDataCache, &appsData)
		if err != nil {
			api.apiLogger.Printf("[ERROR] Couldn't unmarshall apps %v", string(appsDataCache))
			errorData.Message = "Internal server error/Cannot unmarshal apps from cache"
			errorData.StatusCode = http.StatusInternalServerError
			response.WriteHeader(http.StatusInternalServerError)
			response.WriteEntity(errorData)
			return
		}
		api.apiLogger.Printf("[DEBUG] Apps  found in cache")
		response.WriteEntity(appsData)
	}

}

// UpdateApp updates app info
func (api *API) UpdateApp(request *restful.Request, response *restful.Response) {

	appData := domain.ApplicationData{}
	errorData := domain.ErrorResponse{}

	err := request.ReadEntity(&appData)
	if err != nil {
		api.apiLogger.Printf("[ERROR] Couldn't read body with error : %+v", err)
		errorData.Message = "Bad Request/ could not read body"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	username := request.QueryParameter("username")
	if username == "" {
		api.apiLogger.Printf("[ERROR] Couldn't read username query parameter")
		errorData.Message = "Bad Request/ empty username"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	userUUID := request.HeaderParameter("USER-UUID")
	userData, err := api.psqlRepo.GetUserDataWithUUID(userUUID)
	if err != nil {
		api.apiLogger.Printf("[ERROR] User id" + userUUID + " not authorized")
		response.AddHeader("WWW-Authenticate", "Basic realm=Protected Area")
		errorData.Message = "User " + userUUID + " is Not Authorized"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
		response.WriteEntity(errorData)
		return
	}

	flag := true

	userData.UserName = username

	if !helpers.CheckUser(userData, userData.Role) {
		flag = false
	}
	if !flag {
		api.apiLogger.Printf("[ERROR] User " + username + " not authorized")
		response.AddHeader("WWW-Authenticate", "Basic realm=Protected Area")
		errorData.Message = "User " + username + " is Not Authorized"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
		response.WriteEntity(errorData)
		return
	}

	if !helpers.CheckAppsExist(userData.Applications, []*domain.ApplicationData{&appData}) {
		api.apiLogger.Printf("[ERROR] User " + username + " not authorized")
		response.AddHeader("WWW-Authenticate", "Basic realm=Protected Area")
		errorData.Message = "User " + username + " is Not Authorized"
		errorData.StatusCode = http.StatusForbidden
		response.WriteHeader(http.StatusForbidden)
		response.WriteEntity(errorData)
		return
	}

	nowTime := time.Now()
	appData.UpdatedTimestamp = nowTime

	err = api.psqlRepo.UpdateAppData(&appData)
	if err != nil {
		errorData.Message = "Internal error / updating app data in postgres"
		errorData.StatusCode = http.StatusInternalServerError
		response.WriteHeader(http.StatusInternalServerError)
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
		api.apiLogger.Printf("[ERROR] Couldn't read appname query parameter")
		errorData.Message = "Bad Request/ empty appname"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	username := request.QueryParameter("username")
	if username == "" {
		api.apiLogger.Printf("[ERROR] Couldn't read username query parameter")
		errorData.Message = "Bad Request/ empty username"
		errorData.StatusCode = http.StatusBadRequest
		response.WriteHeader(http.StatusBadRequest)
		response.WriteEntity(errorData)
		return
	}

	err := api.psqlRepo.DeleteAppData(appname, username)
	if err != nil {
		api.apiLogger.Printf("[ERROR] App %v not found", appname)
		errorData.Message = "App not found"
		errorData.StatusCode = http.StatusNotFound
		response.WriteHeader(http.StatusNotFound)
		response.WriteEntity(errorData)
		return
	}

	response.Write([]byte("App deleted succesfully"))
}
