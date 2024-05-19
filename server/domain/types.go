package domain

import (
	"time"
)

// UserData represents user information
type UserData struct {
	JoinedDate             *time.Time      `json:"joined_date,omitempty"`
	UserTimeout            *time.Time      `json:"user_timeout,omitempty"`
	LastTimeOnline         *time.Time      `json:"last_time_online,omitempty"`
	OTPData                OneTimePassData `json:"otp_data,omitempty"`
	Email                  string          `json:"email,omitempty"`
	UserName               string          `json:"username"`
	Password               string          `json:"password,omitempty"`
	Role                   string          `json:"role,omitempty"`
	UserID                 string          `json:"user_id,omitempty"`
	BirthDate              string          `json:"birth_date,omitempty"`
	JobRole                string          `json:"job_role,omitempty"`
	FullName               string          `json:"full_name,omitempty"`
	Applications           []string        `json:"applications,omitempty"`
	NrDeployedApps         int             `json:"nr_deployed_apps"`
	UserLimitTimeout       int             `json:"user_limit_timeout"`
	UserLimitLoginAttempts int             `json:"user_limit_login_attempts"`
	UserLocked             bool            `json:"user_locked"`
	WantNotify             bool            `json:"want_notify"`
}

// OneTimePassData represents fields for otp enable/disable + secret and auth url
type OneTimePassData struct {
	OTPSecret   string `json:"otp_secret"`
	OTPAuthURL  string `json:"otp_auth_url"`
	OTPEnabled  bool   `json:"otp_enabled"`
	OTPVerified bool   `json:"otp_verified"`
}

// OTPInput represents credentials for OTP
type OTPInput struct {
	Token string `json:"token,omitempty"`
}

// GenerateOTPResponse represents response for generate OTP token
type GenerateOTPResponse struct {
	Key string `json:"base32"`
	URL string `json:"otp_auth_url"`
}

// ApplicationdData represents app information
type ApplicationData struct {
	UpdatedTimestamp time.Time `json:"updated_timestamp"`
	CreatedTimestamp time.Time `json:"created_timestamp"`
	Port             *int      `json:"port,omitempty"`
	IpAddress        *string   `json:"ip_address,omitempty"`
	FlagArguments    string    `json:"flag_arguments,omitempty"`
	Description      string    `json:"description"`
	Owner            string    `json:"owner"`
	Namespace        string    `json:"namespace,omitempty"`
	ParamArguments   string    `json:"param_arguments,omitempty"`
	Name             string    `json:"name"`
	ScheduleType     string    `json:"schedule_type,omitempty"`
	SubgroupFiles    []string  `json:"subgroup_files,omitempty"`
	AlertIDs         []string  `json:"alert_ids,omitempty"`
	IsMain           bool      `json:"is_main,omitempty"`
	IsRunning        bool      `json:"is_running"`
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
	Response  []*ApplicationData
	Errors    []ErrorResponse
	QueryInfo AppsMetaInfo
}

// FormData represents form info
type FormData struct {
	BadFeatures          string `json:"bad_features"`
	GoodFeatures         string `json:"good_features"`
	ProjectLikeRate      string `json:"project_like_rate"`
	FriendsRecommendRate string `json:"friends_recommend_rate"`
	ProjectIssues        string `json:"project_issues"`
	ProjectHasIssues     string `json:"project_has_issues"`
	ProjectSuggestions   string `json:"project_suggestions"`
	ID                   int    `json:"id"`
}

// FormStatistics represents an aggregation info over form table
type FormStatistics struct {
	Timestamp                   string   `json:"form_timestamp"`
	TotalBadFeatures            []string `json:"total_bad_features"`
	TotalGoodFeatures           []string `json:"total_good_features"`
	TotalProjectIssues          []string `json:"total_project_issues"`
	TotalProjectSuggestions     []string `json:"total_project_suggestions"`
	AverageProjectLikeRate      float64  `json:"average_project_like_rate"`
	AverageFriendsRecommendRate float64  `json:"average_friends_recommend_rate"`
}

// QueryResponse represents info for register/update/delete/schedule resources
type QueryResponse struct {
	Message           string   `json:"message"`
	ResourcesAffected []string `json:"resources_affected,omitempty"`
}

// GetLogsFromPod represents info about pod
type GetLogsFromPod struct {
	AppName      string   `json:"app_name"`
	PrintMessage []string `json:"print_message"`
}

// PodContainerMetrics represents info regarding metrics of a pod container
type PodContainerMetrics struct {
	PodContainerName string
	CPUMemoryMetrics []float64
}

// DockerFile represents fields used to create a Dockerfile
type DockerFile struct {
	User               string
	Workdir            string
	Copy               string
	CopyPy             string
	CopyJs             string
	From               string
	SecondStageWorkdir string
	SecondStageCopy    string
	SecondStageFrom    string
	SecondStageRun     string
	Env                string
	Label              string
	Run                string
	RunC               string
	RunPy              string
	Arg                string
	CopyArgs           []string
	Shell              []string
	Cmd                []string
	RunApt             []string
	Volume             []string
	EntryPoint         []string
	ExposePort         int32
}

// VTResponse represents response coming from file analysis with VT
type VTResponse struct {
	Links      VTResponseLinks      `json:"links"`
	Type       string               `json:"type"`
	ID         string               `json:"id"`
	Attributes VTResponseAttributes `json:"attributes"`
}

// VTResponseAttributes represents vt response attributes
type VTResponseAttributes struct {
	Results struct {
		Bkav                  VTResponseResult `json:"Bkav"`
		Lionic                VTResponseResult `json:"Lionic"`
		Tehtris               VTResponseResult `json:"tehtris"`
		DrWeb                 VTResponseResult `json:"DrWeb"`
		ClamAV                VTResponseResult `json:"ClamAV"`
		FireEye               VTResponseResult `json:"FireEye"`
		CATQuickHeal          VTResponseResult `json:"CAT-QuickHeal"`
		Skyhigh               VTResponseResult `json:"Skyhigh"`
		McAfee                VTResponseResult `json:"McAfee"`
		Malwarebytes          VTResponseResult `json:"Malwarebytes"`
		VIPRE                 VTResponseResult `json:"VIPRE"`
		Sangfor               VTResponseResult `json:"Sangfor"`
		K7AntiVirus           VTResponseResult `json:"K7AntiVirus"`
		Alibaba               VTResponseResult `json:"Alibaba"`
		K7GW                  VTResponseResult `json:"K7GW"`
		Trustlook             VTResponseResult `json:"Trustlook"`
		BitDefenderTheta      VTResponseResult `json:"BitDefenderTheta"`
		VirIT                 VTResponseResult `json:"VirIT"`
		SymantecMobileInsight VTResponseResult `json:"SymantecMobileInsight"`
		Symantec              VTResponseResult `json:"Symantec"`
		Elastic               VTResponseResult `json:"Elastic"`
		ESETNOD32             VTResponseResult `json:"ESET-NOD32"`
		APEX                  VTResponseResult `json:"APEX"`
		TrendMicroHouseCall   VTResponseResult `json:"TrendMicro-HouseCall"`
		Avast                 VTResponseResult `json:"Avast"`
		Cynet                 VTResponseResult `json:"Cynet"`
		Kaspersky             VTResponseResult `json:"Kaspersky"`
		BitDefender           VTResponseResult `json:"BitDefender"`
		NANOAntivirus         VTResponseResult `json:"NANO-Antivirus"`
		ViRobot               VTResponseResult `json:"ViRobot"`
		MicroWorldEScan       VTResponseResult `json:"MicroWorld-eScan"`
		Rising                VTResponseResult `json:"Rising"`
		TACHYON               VTResponseResult `json:"TACHYON"`
		Sophos                VTResponseResult `json:"Sophos"`
		FSecure               VTResponseResult `json:"F-Secure"`
		Baidu                 VTResponseResult `json:"Baidu"`
		Zillya                VTResponseResult `json:"Zillya"`
		TrendMicro            VTResponseResult `json:"TrendMicro"`
		SentinelOne           VTResponseResult `json:"SentinelOne"`
		Trapmine              VTResponseResult `json:"Trapmine"`
		CMC                   VTResponseResult `json:"CMC"`
		Emsisoft              VTResponseResult `json:"Emsisoft"`
		Paloalto              VTResponseResult `json:"Paloalto"`
		AvastMobile           VTResponseResult `json:"Avast-Mobile"`
		Jiangmin              VTResponseResult `json:"Jiangmin"`
		Webroot               VTResponseResult `json:"Webroot"`
		Google                VTResponseResult `json:"Google"`
		Avira                 VTResponseResult `json:"Avira"`
		AntiyAVL              VTResponseResult `json:"Antiy-AVL"`
		Kingsoft              VTResponseResult `json:"Kingsoft"`
		Microsoft             VTResponseResult `json:"Microsoft"`
		Gridinsoft            VTResponseResult `json:"Gridinsoft"`
		Xcitium               VTResponseResult `json:"Xcitium"`
		Arcabit               VTResponseResult `json:"Arcabit"`
		SUPERAntiSpyware      VTResponseResult `json:"SUPERAntiSpyware"`
		ZoneAlarm             VTResponseResult `json:"ZoneAlarm"`
		GData                 VTResponseResult `json:"GData"`
		Varist                VTResponseResult `json:"Varist"`
		BitDefenderFalx       VTResponseResult `json:"BitDefenderFalx"`
		AhnLabV3              VTResponseResult `json:"AhnLab-V3"`
		Acronis               VTResponseResult `json:"Acronis"`
		VBA32                 VTResponseResult `json:"VBA32"`
		ALYac                 VTResponseResult `json:"ALYac"`
		MAX                   VTResponseResult `json:"MAX"`
		DeepInstinct          VTResponseResult `json:"DeepInstinct"`
		Cylance               VTResponseResult `json:"Cylance"`
		Zoner                 VTResponseResult `json:"Zoner"`
		Tencent               VTResponseResult `json:"Tencent"`
		Yandex                VTResponseResult `json:"Yandex"`
		Ikarus                VTResponseResult `json:"Ikarus"`
		MaxSecure             VTResponseResult `json:"MaxSecure"`
		Fortinet              VTResponseResult `json:"Fortinet"`
		AVG                   VTResponseResult `json:"AVG"`
		Cybereason            VTResponseResult `json:"Cybereason"`
		Panda                 VTResponseResult `json:"Panda"`
		CrowdStrike           VTResponseResult `json:"CrowdStrike"`
	} `json:"results"`
	Status string          `json:"status"`
	Stats  VTResponseStats `json:"stats"`
	Date   int             `json:"date"`
}

// VTResponseStats represents vt response stats
type VTResponseStats struct {
	Harmless         int `json:"harmless"`
	TypeUnsupported  int `json:"type-unsupported"`
	Suspicious       int `json:"suspicious"`
	ConfirmedTimeout int `json:"confirmed-timeout"`
	Timeout          int `json:"timeout"`
	Failure          int `json:"failure"`
	Malicious        int `json:"malicious"`
	Undetected       int `json:"undetected"`
}

// VTResponseResult represents info about every analyzer results
type VTResponseResult struct {
	Result        interface{} `json:"result"`
	Category      string      `json:"category"`
	EngineName    string      `json:"engine_name"`
	EngineVersion string      `json:"engine_version"`
	Method        string      `json:"method"`
	EngineUpdate  string      `json:"engine_update"`
}

// VTResponseLinks represents response links
type VTResponseLinks struct {
	Item string `json:"item"`
	Self string `json:"self"`
}

// GrafanaDataSourceInfo represents graphite results for every metric
type GrafanaDataSourceInfo struct {
	Target     string       `json:"target"`
	Datapoints [][]*float64 `json:"datapoints"`
}

// GrafanaDataSourceResponse represents type for grafana data source response
type GrafanaDataSourceResponse []GrafanaDataSourceInfo

// RelativeTimeRange represents info about time range alert
type RelativeTimeRange struct {
	From int64 `json:"from"`
	To   int64 `json:"to"`
}

// Model represents struct for alert model
type Model struct {
	Datasource    Datasource  `json:"datasource,omitempty"`
	Target        string      `json:"target,omitempty"`
	Type          string      `json:"type,omitempty"`
	Expression    string      `json:"expression,omitempty"`
	Reducer       string      `json:"reducer,omitempty"`
	RefID         string      `json:"refId"`
	Conditions    []Condition `json:"conditions,omitempty"`
	IntervalMs    int         `json:"intervalMs,omitempty"`
	MaxDataPoints int         `json:"maxDataPoints,omitempty"`
	Hide          bool        `json:"hide"`
}

// Data represents struct for alert data
type Data struct {
	RefID             string            `json:"refId"`
	QueryType         string            `json:"queryType"`
	DatasourceUUID    string            `json:"datasourceUid"`
	Reducer           string            `json:"reducer"`
	Model             Model             `json:"model"`
	RelativeTimeRange RelativeTimeRange `json:"relativeTimeRange"`
}

// Datasource represents struct for grafana alert datasource
type Datasource struct {
	Type string `json:"type,omitempty"`
	UID  string `json:"uid,omitempty"`
}

// Condition represents struct for grafana alert condition
type Condition struct {
	Evaluator Evaluator `json:"evaluator"`
	Reducer   Reducer   `json:"reducer"`
	Type      string    `json:"type"`
	Operator  Operator  `json:"operator"`
	Query     Query     `json:"query"`
}

// Evaluator represents struct for grafana alert evaluator
type Evaluator struct {
	Type   string `json:"type"`
	Params []int  `json:"params"`
}

// Operator represents struct for grafana alert operator
type Operator struct {
	Type string `json:"type"`
}

// Query represents struct for grafana alert query
type Query struct {
	Params []string `json:"params"`
}

// Reducer represents struct for grafana alert reducer
type Reducer struct {
	Type   string   `json:"type"`
	Params []string `json:"params"`
}

// Annotations represents struct for grafana alert annotations
type Annotations struct {
	Description string `json:"description"`
	Summary     string `json:"summary"`
}

// GrafanaAlertInfo represents struct for creating an alert rule
type GrafanaAlertInfo struct {
	Annotations  Annotations `json:"annotations"`
	Condition    string      `json:"condition"`
	Updated      string      `json:"updated"`
	FolderUID    string      `json:"folderUID"`
	RuleGroup    string      `json:"ruleGroup"`
	Title        string      `json:"title"`
	Provenance   string      `json:"provenance,omitempty"`
	UID          string      `json:"uid"`
	For          string      `json:"for"`
	NoDataState  string      `json:"noDataState"`
	ExecErrState string      `json:"execErrState"`
	Data         []Data      `json:"data"`
	OrgID        int         `json:"orgID"`
	ID           int         `json:"id"`
	IsPaused     bool        `json:"isPaused"`
}

// AlertNotification represents struct for alert notification info
type AlertNotification struct {
	NewState string `json:"newState"`
}

// AlertNotificationResponse represents type for alert notification response
type AlertNotificationResponse []AlertNotification

// ErrorLine represents line of error from docker
type ErrorLine struct {
	Error       string      `json:"error"`
	ErrorDetail ErrorDetail `json:"errorDetail"`
}

// ErrorDetail represents error message
type ErrorDetail struct {
	Message string `json:"message"`
}

// TaskItem represents info for hybrid algorithm between Round Robin and Shortest Job First
type TaskItem struct {
	Name     string `json:"name"`
	Duration string `json:"duration"`
}

// Item is something we manage in a priority queue.
type Item struct {
	Name                string
	InitialTaskDuration time.Duration
	TaskDuration        time.Duration
	Index               int
}
