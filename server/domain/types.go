package domain

import "time"

// UserData represents user information
type UserData struct {
	JoinedDate     time.Time `json:"joined_date,omitempty"`
	LastTimeOnline time.Time `json:"last_time_online,omitempty"`
	UserName       string    `json:"username"`
	Password       string    `json:"password,omitempty"`
	Email          string    `json:"email,omitempty"`
	CityAddress    string    `json:"city_address,omitempty"`
	WantNotify     string    `json:"want_notify,omitempty"`
	Role           string    `json:"role,omitempty"`
	UserID         string    `json:"user_id,omitempty"`
	FullName       string    `json:"full_name,omitempty"`
	BirthDate      string    `json:"birth_date,omitempty"`
	Applications   []string  `json:"applications,omitempty"`
}

// ApplicationdData represents app information
type ApplicationData struct {
	CreatedTimestamp time.Time `json:"created_timestamp"`
	UpdatedTimestamp time.Time `json:"updated_timestamp"`
	Name             string    `json:"name"`
	Description      string    `json:"description"`
	IsRunning        string    `json:"is_running"`
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
