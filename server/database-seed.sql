CREATE TABLE users(username VARCHAR(30) PRIMARY KEY, password VARCHAR(50), email VARCHAR(50), full_name VARCHAR(100), nr_deployed_apps INTEGER,
 job_role VARCHAR(50), birth_date VARCHAR(30), joined_date TIMESTAMPTZ, last_time_online TIMESTAMPTZ, want_notify BOOLEAN, 
 applications text[], user_id VARCHAR(128), role VARCHAR(256) );
CREATE TABLE apps(name VARCHAR(30) PRIMARY KEY , owner VARCHAR(30), description TEXT, flag_arguments TEXT, param_arguments TEXT, is_running BOOLEAN, 
is_main BOOLEAN, subgroup_files text[], created_timestamp timestamptz, updated_timestamp timestamptz, namespace TEXT, schedule_type TEXT);

INSERT INTO users (username, password, email, full_name, nr_deployed_apps, job_role, birth_date, joined_date, last_time_online ,want_notify,applications,user_id, role) 
VALUES ('admin', 'admin', 'admin@admin.com', 'Unknown', 0, 'admin', 'Unknown', '2023-01-01 06:30:30+00', '2023-01-01 06:30:30+00',  'false',  array[]::text[], 'admin', 'admin')