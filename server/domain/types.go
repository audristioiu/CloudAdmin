package domain

// UserData represents user information
type UserData struct {
	UserName     string            `json:"username"`
	Password     string            `json:"password,omitempty"`
	CityAddress  string            `json:"city_address,omitempty"`
	WantNotify   bool              `json:"want_notify,omitempty"`
	Applications []ApplicationData `json:"applications,omitempty"`
	Role         string            `json:"role,omitempty"`
	UserID       string            `json:"user_id,omitempty"`
}

// ApplicationdData represents app information
type ApplicationData struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	IsRunning   bool   `json:"is_running"`
}

// ErrorResponse represents error info
type ErrorResponse struct {
	StatusCode int    `json:"status_code"`
	Message    string `json:"message"`
	Error      error  `json:"error,omitempty"`
}
