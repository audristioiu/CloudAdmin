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
