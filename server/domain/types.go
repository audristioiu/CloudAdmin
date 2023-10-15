package domain

import "time"

// UserData represents user information
type UserData struct {
	JoinedDate     *time.Time `json:"joined_date,omitempty"`
	LastTimeOnline *time.Time `json:"last_time_online,omitempty"`
	NrDeployedApps int        `json:"nr_deployed_apps"`
	WantNotify     bool       `json:"want_notify,omitempty"`
	Email          string     `json:"email,omitempty"`
	UserName       string     `json:"username"`
	Password       string     `json:"password,omitempty"`
	Role           string     `json:"role,omitempty"`
	UserID         string     `json:"user_id,omitempty"`
	FullName       string     `json:"full_name,omitempty"`
	BirthDate      string     `json:"birth_date,omitempty"`
	JobRole        string     `json:"job_role,omitempty"`
	Applications   []string   `json:"applications,omitempty"`
}

// ApplicationdData represents app information
type ApplicationData struct {
	CreatedTimestamp time.Time `json:"created_timestamp"`
	UpdatedTimestamp time.Time `json:"updated_timestamp"`
	Name             string    `json:"name"`
	FlagArguments    string    `json:"flag_arguments,omitempty"`
	ParamArguments   string    `json:"param_arguments,omitempty"`
	IsMain           bool      `json:"is_main,omitempty"`
	SubgroupFiles    []string  `json:"subgroup_files,omitempty"`
	Description      string    `json:"description"`
	IsRunning        bool      `json:"is_running"`
	Owner            string    `json:"owner"`
	Namespace        string    `json:"namespace,omitempty"`
	ScheduleType     string    `json:"schedule_type,omitempty"`
}

// ErrorResponse represents error info
type ErrorResponse struct {
	Message    string `json:"message"`
	StatusCode int    `json:"status_code"`
}

// GetAppInfo represents counts about apps aggregates
type GetAppInfo struct {
	MainAppsByOwnerCount    int64 `json:"main_apps_owner_count"`
	MainAppsTotalCount      int64 `json:"main_apps_total_count"`
	RunningAppsByOwnerCount int64 `json:"running_apps_owner_count"`
	RunningAppsTotalCount   int64 `json:"running_apps_total_count"`
}

// AppsAggregatesInfo represents apps info for aggregates response
type AppsAggregatesInfo struct {
	QueryInfo GetAppInfo
}

// AppsMetaInfo represents meta info about apps
type AppsMetaInfo struct {
	Total          int `json:"total"`
	ResourcesCount int `json:"resources_count"`
}

// GetApplicationsData represents get apps info
type GetApplicationsData struct {
	QueryInfo AppsMetaInfo
	Response  []*ApplicationData
	Errors    []ErrorResponse
}

// QueryResponse represents info for register/update/delete/schedule resources
type QueryResponse struct {
	Message           string   `json:"message"`
	ResourcesAffected []string `json:"resources_affected"`
}

// GetLogsFromPod represents info about pod
type GetLogsFromPod struct {
	PrintMessage string `json:"print_message"`
	AppName      string `json:"app_name"`
}

// DockerFile represents fields used to create a Dockerfile
type DockerFile struct {
	From       string
	Workdir    string
	Copy       string
	CopyArgs   []string
	EntryPoint []string
	Volume     []string
	Run        string
	RunApt     []string
	Cmd        []string
	Shell      []string
	User       string
	Arg        string
	Label      string
	Env        string
	ExposePort int
}
