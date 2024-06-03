package domain

// Config represents project config
type Config struct {
	PostgresConfig
	DockerConfig
	S3Config
	GrafanaConfig

	EnableCPUProfiler bool `env:"ENABLE_CPU_PROFILER"`
	EnableS3          bool `env:"ENABLE_S3"`
	EnableKubeMetrics bool `env:"ENABLE_KUBERNETES_METRICS"`

	KubeConfigPath string `env:"KUBE_CONFIG_PATH"`

	GraphiteHost string `env:"GRAPHITE_HOST"`

	MaxRequestPerMinute int `env:"MAX_REQ_PER_MINUTE"`

	VirusTotalKey string `env:"VIRUSTOTAL_KEY"`

	CertFile    string `env:"CERT_FILE"`
	CertKeyFile string `env:"CERT_KEY_FILE"`
}

// PostgresConfig represents config for PostgreSQL Database
type PostgresConfig struct {
	PsqlUser string `env:"POSTGRES_USER"`
	PsqlPass string `env:"POSTGRES_PASSWORD"`
	DbName   string `env:"POSTGRES_DB"`
	DbHost   string `env:"POSTGRES_HOST"`
	DbPort   int    `env:"POSTGRES_PORT"`
}

// DockerConfig represents config for Docker Client
type DockerConfig struct {
	RegistryID     string `env:"DOCKER_REGISTRY_ID"`
	DockerUsername string `env:"DOCKER_USERNAME"`
	DockerPassword string `env:"DOCKER_PASSWORD"`
}

// S3Config represents config for S3 Client
type S3Config struct {
	AccessKey string `env:"AWS_ACCESS_KEY"`
	SecretKey string `env:"AWS_SECRET_KEY"`
	Region    string `env:"AWS_S3_REGION"`
	Bucket    string `env:"AWS_S3_BUCKET"`
}

// GrafanaConfig represents config for Grafana Client
type GrafanaConfig struct {
	GrafanaAdminUser string `env:"GF_SECURITY_ADMIN_USER"`
	GrafanaAdminPass string `env:"GF_SECURITY_ADMIN_PASSWORD"`
	Host             string `env:"GF_HOST"`
	DataSourceUUID   string `env:"GF_DATASOURCE_UUID"`
	FolderUID        string `env:"GF_FOLDER_UID"`
}
