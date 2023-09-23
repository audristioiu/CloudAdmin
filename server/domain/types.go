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
}

// ErrorResponse represents error info
type ErrorResponse struct {
	Message    string `json:"message"`
	StatusCode int    `json:"status_code"`
}

// GetApplicationsData represents get apps info
type GetApplicationsData struct {
	Response []*ApplicationData
	Errors   []ErrorResponse
}

// QueryResponse represents info for register/update/delete resources
type QueryResponse struct {
	Message           string   `json:"message"`
	ResourcesAffected []string `json:"resources_affected"`
}

// DockerFile represents fields used to create a Dockerfile
type DockerFile struct {
	From       string
	Workdir    string
	Copy       string
	EntryPoint []string
	Volume     []string
	Run        string
	Cmd        []string
	Shell      []string
	User       string
	Arg        string
	Label      string
	Env        string
	ExposePort int
}
