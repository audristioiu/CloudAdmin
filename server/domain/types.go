package domain

import (
	"time"
)

// UserData represents user information
type UserData struct {
	JoinedDate             *time.Time      `json:"joined_date,omitempty"`
	LastTimeOnline         *time.Time      `json:"last_time_online,omitempty"`
	FullName               string          `json:"full_name,omitempty"`
	Email                  string          `json:"email,omitempty"`
	UserName               string          `json:"username"`
	Password               string          `json:"password,omitempty"`
	Role                   string          `json:"role,omitempty"`
	UserID                 string          `json:"user_id,omitempty"`
	BirthDate              string          `json:"birth_date,omitempty"`
	JobRole                string          `json:"job_role,omitempty"`
	Applications           []string        `json:"applications,omitempty"`
	UserLocked             bool            `json:"user_locked"`
	UserTimeout            *time.Time      `json:"user_timeout,omitempty"`
	UserLimitLoginAttempts int             `json:"user_limit_login_attempts"`
	UserLimitTimeout       int             `json:"user_limit_timeout"`
	NrDeployedApps         int             `json:"nr_deployed_apps"`
	WantNotify             bool            `json:"want_notify"`
	OTPData                OneTimePassData `json:"otp_data,omitempty"`
}

// OneTimePassData represents fields for otp enable/disable + secret and auth url
type OneTimePassData struct {
	OTPEnabled  bool   `json:"otp_enabled"`
	OTPVerified bool   `json:"otp_verified"`
	OTPSecret   string `json:"otp_secret"`
	OTPAuthURL  string `json:"otp_auth_url"`
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
	CreatedTimestamp time.Time `json:"created_timestamp"`
	UpdatedTimestamp time.Time `json:"updated_timestamp"`
	Name             string    `json:"name"`
	FlagArguments    string    `json:"flag_arguments,omitempty"`
	ParamArguments   string    `json:"param_arguments,omitempty"`
	Description      string    `json:"description"`
	Owner            string    `json:"owner"`
	Namespace        string    `json:"namespace,omitempty"`
	Port             *int      `json:"port,omitempty"`
	IpAddress        *string   `json:"ip_address,omitempty"`
	ScheduleType     string    `json:"schedule_type,omitempty"`
	SubgroupFiles    []string  `json:"subgroup_files,omitempty"`
	IsMain           bool      `json:"is_main,omitempty"`
	IsRunning        bool      `json:"is_running"`
	AlertIDs         []string  `json:"alert_ids,omitempty"`
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
	ID                   int    `json:"id"`
	BadFeatures          string `json:"bad_features"`
	GoodFeatures         string `json:"good_features"`
	ProjectLikeRate      string `json:"project_like_rate"`
	FriendsRecommendRate string `json:"friends_recommend_rate"`
	ProjectIssues        string `json:"project_issues"`
	ProjectHasIssues     string `json:"project_has_issues"`
	ProjectSuggestions   string `json:"project_suggestions"`
}

// FormStatistics represents an aggregation info over form table
type FormStatistics struct {
	AverageProjectLikeRate      float64  `json:"average_project_like_rate"`
	AverageFriendsRecommendRate float64  `json:"average_friends_recommend_rate"`
	TotalBadFeatures            []string `json:"total_bad_features"`
	TotalGoodFeatures           []string `json:"total_good_features"`
	TotalProjectIssues          []string `json:"total_project_issues"`
	TotalProjectSuggestions     []string `json:"total_project_suggestions"`
}

// QueryResponse represents info for register/update/delete/schedule resources
type QueryResponse struct {
	Message           string   `json:"message"`
	ResourcesAffected []string `json:"resources_affected,omitempty"`
}

// GetLogsFromPod represents info about pod
type GetLogsFromPod struct {
	PrintMessage []string `json:"print_message"`
	AppName      string   `json:"app_name"`
}

// PodContainerMetrics represents info regarding metrics of a pod container
type PodContainerMetrics struct {
	CPUMemoryMetrics []float64
	PodContainerName string
}

// DockerFile represents fields used to create a Dockerfile
type DockerFile struct {
	User       string
	Workdir    string
	Copy       string
	From       string
	Env        string
	Label      string
	Run        string
	Arg        string
	CopyArgs   []string
	Shell      []string
	Cmd        []string
	RunApt     []string
	Volume     []string
	EntryPoint []string
	ExposePort int32
}

// VTResponse represents response coming from file analysis with VT
type VTResponse struct {
	Attributes struct {
		Date   int    `json:"date"`
		Status string `json:"status"`
		Stats  struct {
			Harmless         int `json:"harmless"`
			TypeUnsupported  int `json:"type-unsupported"`
			Suspicious       int `json:"suspicious"`
			ConfirmedTimeout int `json:"confirmed-timeout"`
			Timeout          int `json:"timeout"`
			Failure          int `json:"failure"`
			Malicious        int `json:"malicious"`
			Undetected       int `json:"undetected"`
		} `json:"stats"`
		Results struct {
			Bkav struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Bkav"`
			Lionic struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Lionic"`
			Tehtris struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion interface{} `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"tehtris"`
			DrWeb struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"DrWeb"`
			ClamAV struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"ClamAV"`
			FireEye struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"FireEye"`
			CATQuickHeal struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"CAT-QuickHeal"`
			Skyhigh struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Skyhigh"`
			McAfee struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"McAfee"`
			Malwarebytes struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Malwarebytes"`
			VIPRE struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"VIPRE"`
			Sangfor struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Sangfor"`
			K7AntiVirus struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"K7AntiVirus"`
			Alibaba struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Alibaba"`
			K7GW struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"K7GW"`
			Trustlook struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Trustlook"`
			BitDefenderTheta struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"BitDefenderTheta"`
			VirIT struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"VirIT"`
			SymantecMobileInsight struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"SymantecMobileInsight"`
			Symantec struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Symantec"`
			Elastic struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Elastic"`
			ESETNOD32 struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"ESET-NOD32"`
			APEX struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"APEX"`
			TrendMicroHouseCall struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"TrendMicro-HouseCall"`
			Avast struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Avast"`
			Cynet struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Cynet"`
			Kaspersky struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Kaspersky"`
			BitDefender struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"BitDefender"`
			NANOAntivirus struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"NANO-Antivirus"`
			ViRobot struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"ViRobot"`
			MicroWorldEScan struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"MicroWorld-eScan"`
			Rising struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Rising"`
			TACHYON struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"TACHYON"`
			Sophos struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Sophos"`
			FSecure struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"F-Secure"`
			Baidu struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Baidu"`
			Zillya struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Zillya"`
			TrendMicro struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"TrendMicro"`
			SentinelOne struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"SentinelOne"`
			Trapmine struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Trapmine"`
			CMC struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"CMC"`
			Emsisoft struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Emsisoft"`
			Paloalto struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Paloalto"`
			AvastMobile struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Avast-Mobile"`
			Jiangmin struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Jiangmin"`
			Webroot struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Webroot"`
			Google struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Google"`
			Avira struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Avira"`
			AntiyAVL struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Antiy-AVL"`
			Kingsoft struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Kingsoft"`
			Microsoft struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Microsoft"`
			Gridinsoft struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Gridinsoft"`
			Xcitium struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Xcitium"`
			Arcabit struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Arcabit"`
			SUPERAntiSpyware struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"SUPERAntiSpyware"`
			ZoneAlarm struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"ZoneAlarm"`
			GData struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"GData"`
			Varist struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Varist"`
			BitDefenderFalx struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"BitDefenderFalx"`
			AhnLabV3 struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"AhnLab-V3"`
			Acronis struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Acronis"`
			VBA32 struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"VBA32"`
			ALYac struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"ALYac"`
			MAX struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"MAX"`
			DeepInstinct struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"DeepInstinct"`
			Cylance struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Cylance"`
			Zoner struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Zoner"`
			Tencent struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Tencent"`
			Yandex struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Yandex"`
			Ikarus struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Ikarus"`
			MaxSecure struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"MaxSecure"`
			Fortinet struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Fortinet"`
			AVG struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"AVG"`
			Cybereason struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Cybereason"`
			Panda struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  string      `json:"engine_update"`
			} `json:"Panda"`
			CrowdStrike struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineVersion string      `json:"engine_version"`
				Result        interface{} `json:"result"`
				Method        string      `json:"method"`
				EngineUpdate  interface{} `json:"engine_update"`
			} `json:"CrowdStrike"`
		} `json:"results"`
	} `json:"attributes"`
	Type  string `json:"type"`
	ID    string `json:"id"`
	Links struct {
		Item string `json:"item"`
		Self string `json:"self"`
	} `json:"links"`
}

// GrafanaDataSourceResponse represents graphite results for every metric
type GrafanaDataSourceResponse struct {
	Target     string       `json:"target"`
	Datapoints [][]*float64 `json:"datapoints"`
}

// RelativeTimeRange represents info about time range alert
type RelativeTimeRange struct {
	From int64 `json:"from"`
	To   int64 `json:"to"`
}

// Model represents struct for alert model
type Model struct {
	Hide          bool        `json:"hide"`
	IntervalMs    int         `json:"intervalMs,omitempty"`
	MaxDataPoints int         `json:"maxDataPoints,omitempty"`
	Target        string      `json:"target,omitempty"`
	Type          string      `json:"type,omitempty"`
	Datasource    Datasource  `json:"datasource,omitempty"`
	Conditions    []Condition `json:"conditions,omitempty"`
	Expression    string      `json:"expression,omitempty"`
	Reducer       string      `json:"reducer,omitempty"`
	RefID         string      `json:"refId"`
}

// Data represents struct for alert data
type Data struct {
	RefID             string            `json:"refId"`
	QueryType         string            `json:"queryType"`
	RelativeTimeRange RelativeTimeRange `json:"relativeTimeRange"`
	DatasourceUUID    string            `json:"datasourceUid"`
	Model             Model             `json:"model"`
	Reducer           string            `json:"reducer"`
}

// Datasource represents struct for grafana alert datasource
type Datasource struct {
	Type string `json:"type,omitempty"`
	UID  string `json:"uid,omitempty"`
}

// Condition represents struct for grafana alert condition
type Condition struct {
	Type      string    `json:"type"`
	Evaluator Evaluator `json:"evaluator"`
	Operator  Operator  `json:"operator"`
	Query     Query     `json:"query"`
	Reducer   Reducer   `json:"reducer"`
}

// Evaluator represents struct for grafana alert evaluator
type Evaluator struct {
	Params []int  `json:"params"`
	Type   string `json:"type"`
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
	Params []string `json:"params"`
	Type   string   `json:"type"`
}

// Annotations represents struct for grafana alert annotations
type Annotations struct {
	Description string `json:"description"`
	Summary     string `json:"summary"`
}

// GrafanaAlertInfo represents struct for creating an alert rule
type GrafanaAlertInfo struct {
	ID           int         `json:"id"`
	UID          string      `json:"uid"`
	OrgID        int         `json:"orgID"`
	FolderUID    string      `json:"folderUID"`
	RuleGroup    string      `json:"ruleGroup"`
	Title        string      `json:"title"`
	Condition    string      `json:"condition"`
	Data         []Data      `json:"data"`
	Updated      string      `json:"updated"`
	NoDataState  string      `json:"noDataState"`
	ExecErrState string      `json:"execErrState"`
	For          string      `json:"for"`
	Annotations  Annotations `json:"annotations"`
	IsPaused     bool        `json:"isPaused"`
	Provenance   string      `json:"provenance,omitempty"`
}

// AlertNotification represents struct for alert notification response
type AlertNotification struct {
	NewState string `json:"newState"`
}
