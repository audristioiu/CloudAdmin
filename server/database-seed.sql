CREATE TABLE users(username VARCHAR(30) PRIMARY KEY, password VARCHAR(30), email VARCHAR(50), full_name VARCHAR(100), city_address VARCHAR(100), birth_date VARCHAR(30), joined_date TIMESTAMPTZ, 
last_time_online TIMESTAMPTZ, want_notify TEXT, applications text[], user_id VARCHAR(128), role VARCHAR(256) );
CREATE TABLE apps(name VARCHAR(30) PRIMARY KEY , description VARCHAR(100), is_running TEXT, created_timestamp timestamptz, updated_timestamp timestamptz );

INSERT INTO users (username, password, full_name, city_address, birth_date, joined_date, last_time_online, city_address,want_notify,applications,user_id, role) 
VALUES ('admin', 'admin', 'admin@admin.com', 'Unknown', 'Unknown', '2023-01-01 06:30:30+00', '2023-01-01 06:30:30+00', 'Washington Street', 'false',  array[]::text[], 'admin', 'admin')