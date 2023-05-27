package domain

import "time"

// UserData represents user information
type UserData struct {
	UserName       string    `json:"username"`
	Password       string    `json:"password,omitempty"`
	CityAddress    string    `json:"city_address,omitempty"`
	WantNotify     string    `json:"want_notify,omitempty"`
	Applications   []string  `json:"applications,omitempty"`
	Role           string    `json:"role,omitempty"`
	UserID         string    `json:"user_id,omitempty"`
	JoinedDate     time.Time `json:"joined_date,omitempty"`
	LastTimeOnline time.Time `json:"last_time_online,omitempty"`
	FullName       string    `json:"full_name,omitempty"`
	BirthDate      string    `json:"birth_date,omitempty"`
}

// ApplicationdData represents app information
type ApplicationData struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	IsRunning   string `json:"is_running"`
}

// ErrorResponse represents error info
type ErrorResponse struct {
	StatusCode int    `json:"status_code"`
	Message    string `json:"message"`
}
