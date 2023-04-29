CREATE TABLE users(username VARCHAR(30) PRIMARY KEY, password VARCHAR(30), city_address VARCHAR(30), want_notify BOOLEAN, applications text[],
user_id VARCHAR(128), role VARCHAR(256) );
CREATE TABLE apps(name VARCHAR(30) PRIMARY KEY , description VARCHAR(100), is_running BOOLEAN );

INSERT INTO users (username, password, city_address,want_notify,applications,role) VALUES ('admin', 'admin', 'Washington Street', FALSE,  array[]::text[], 'admin')