package helpers

var (
	// GetAppsFilters represents filters that can be used for GetAppsInfo
	GetAppsFilters = []string{"name", "kname", "description", "created_timestamp", "updated_timestamp", "is_running"}
	// GetAppsSortFields represents sort fields that can be used for GetAppsInfo
	GetAppsSortFields = []string{"name", "created_timestamp", "updated_timestamp"}
	// SortDirections represents sort directions
	SortDirections = []string{"asc", "desc"}
	// DefaultNrDeployedApps represents default number of deployed apps for a new registered user
	DefaultNrDeployedApps int = 0
	// ScheduleTypes represents allowed scheduling types
	ScheduleTypes    = []string{"normal", "random_scheduler", "rr_sjf_scheduler", "multi_qos_scheduler"}
	mapCodeExtension = map[string]string{
		"c":    "c",
		"cpp":  "c++",
		"py":   "python",
		"js":   "nodejs",
		"java": "java",
		"go":   "golang",
	}
)
