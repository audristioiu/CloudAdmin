CREATE TABLE users(username VARCHAR(30) PRIMARY KEY, password TEXT, email VARCHAR(50), full_name VARCHAR(100), nr_deployed_apps INTEGER,
 job_role VARCHAR(50), birth_date VARCHAR(30), joined_date TIMESTAMPTZ, last_time_online TIMESTAMPTZ, want_notify BOOLEAN, 
 applications TEXT[], user_locked BOOLEAN, user_timeout TIMESTAMPTZ,user_limit_login_attempts INTEGER, user_limit_timeout INTEGER,
user_id VARCHAR(128), role VARCHAR(256), otp_enabled BOOLEAN, otp_verified BOOLEAN,otp_secret TEXT, otp_auth_url TEXT);
CREATE TABLE apps(name TEXT PRIMARY KEY , owner VARCHAR(30), description TEXT, flag_arguments TEXT, param_arguments TEXT, is_running BOOLEAN, 
is_main BOOLEAN, subgroup_files TEXT[], created_timestamp timestamptz, updated_timestamp timestamptz, namespace TEXT, schedule_type TEXT, port INTEGER,
ip_address TEXT, alert_ids TEXT[]);
CREATE TABLE forms(id SERIAL PRIMARY KEY, bad_features TEXT, project_like_rate TEXT, friends_recommend_rate TEXT, project_issues TEXT,
project_has_issues TEXT,project_suggestions TEXT, good_features TEXT);

INSERT INTO users (username, password, email, full_name, nr_deployed_apps, job_role, birth_date, joined_date, last_time_online ,want_notify,applications,
user_locked, user_timeout, user_limit_login_attempts, user_limit_timeout, user_id, role, otp_enabled, otp_verified, otp_secret, otp_auth_url) 
VALUES ('admin', 'admin', 'admin@admin.com', 'N/A', 0, 'N/A', 'N/A', '2023-01-01 06:30:30+00', '2023-01-01 06:30:30+00', false, 
 array[]::TEXT[], false, '2023-01-01 06:30:30+00',5, 3,'N/A', 'N/A', false, false, 'N/A', 'N/A')