package helpers

var (
	//filters that can be used for GetAppsInfo
	GetAppsFilters = []string{"name", "kname", "description", "created_timestamp", "updated_timestamp", "is_running"}
	// sort fields that can be used for GetAppsInfo
	GetAppsSortFields = []string{"name", "created_timestamp", "updated_timestamp"}
	//sort directions
	SortDirections = []string{"asc", "desc"}
	//default number of deployed apps for a new registered user
	DefaultNrDeployedApps int = 0
)
