package helpers

var (
	// GetAppsFilters represents filters that can be used for GetAppsInfo
	GetAppsFilters = []string{"name", "kname", "description", "created_timestamp", "updated_timestamp", "is_running",
		"port", "ip_address", "schedule_type"}
	// GetAppsSortFields represents sort fields that can be used for GetAppsInfo
	GetAppsSortFields = []string{"name", "created_timestamp", "updated_timestamp"}
	// SortDirections represents sort directions
	SortDirections = []string{"asc", "desc"}
	// DefaultNrDeployedApps represents default number of deployed apps for a new registered user
	DefaultNrDeployedApps int = 0
	// ScheduleTypes represents allowed scheduling types
	ScheduleTypes = []string{"normal", "random_scheduler", "rr_sjf_scheduler", "multi_qos_scheduler"}
	// LoginAttempts represents number of login attempts before timeout
	LoginAttempts = 5
	// TimeoutLimit represents limit of timeouts a user has
	TimeoutLimit = 3
	//MetricsName represents slice of metrics that are unregistered when closing app
	MetricsName = []string{"applications.get", "applications.update", "applications.register",
		"applications.schedule", "applications.get_pod_results", "users.get.profile", "users.update.profile",
		"users_failed_login, user_profile_latency.response, get_apps_latency.response, schedule_apps_latency.response"}
	mapCodeExtension = map[string]string{
		"c":    "c",
		"cpp":  "c++",
		"py":   "python",
		"js":   "nodejs",
		"java": "java",
		"go":   "golang",
	}
)
