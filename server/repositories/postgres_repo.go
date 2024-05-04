package repositories

import (
	"cloudadmin/domain"
	"cloudadmin/helpers"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype/zeronull"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// PostgresSqlRepo represents info about PostgreSql
type PostgreSqlRepo struct {
	ctx        context.Context
	conn       *pgxpool.Pool
	psqlLogger *zap.Logger
}

// NewPostgreSqlRepo returns a new PostgreSql repo
func NewPostgreSqlRepo(ctx context.Context, username, password, host, databaseName string, port int, logger *zap.Logger) *PostgreSqlRepo {
	url := fmt.Sprintf("postgres://%s:%s@%s:%d/%s", username, password, host, port, databaseName)

	dbPool, err := pgxpool.New(ctx, url)
	if err != nil {
		logger.Error(" could not connect to database", zap.Error(err))
		return nil
	}

	// check connection
	err = dbPool.Ping(ctx)
	if err != nil {
		logger.Error(" could not ping", zap.Error(err))
		return nil
	}

	return &PostgreSqlRepo{
		ctx:        ctx,
		conn:       dbPool,
		psqlLogger: logger,
	}
}

// InsertUserData inserts user in PostgreSql table
func (p *PostgreSqlRepo) InsertUserData(userData *domain.UserData) error {
	if userData.Password != "" {
		userData.Password = helpers.HashPassword(userData.Password)
	}

	newUserData := domain.UserData{}
	insertStatement := `INSERT INTO users (username, password, email, full_name, nr_deployed_apps, job_role,
						birth_date, joined_date, last_time_online, want_notify,applications,user_locked,user_timeout, 
						user_limit_login_attempts, user_limit_timeout,user_id, role,otp_enabled, otp_verified, otp_secret, otp_auth_url) 
						VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,$16,$17,$18,$19,$20,$21) RETURNING username`

	row := p.conn.QueryRow(p.ctx, insertStatement, userData.UserName, userData.Password, userData.Email,
		userData.FullName, userData.NrDeployedApps, userData.JobRole, userData.BirthDate, userData.JoinedDate, userData.LastTimeOnline,
		userData.WantNotify, userData.Applications, userData.UserLocked, userData.UserTimeout, userData.UserLimitLoginAttempts,
		userData.UserLimitTimeout, userData.UserID, userData.Role, userData.OTPData.OTPEnabled, userData.OTPData.OTPVerified,
		userData.OTPData.OTPSecret, userData.OTPData.OTPAuthURL)
	err := row.Scan(&newUserData.UserName)
	if err != nil {
		p.psqlLogger.Error(" could not insert data", zap.Error(err))
		return err
	}
	p.psqlLogger.Info("Successfuly inserted user", zap.String("user_name", newUserData.UserName))
	return nil
}

// GetUserData retrieves user from PostgreSql table
func (p *PostgreSqlRepo) GetUserData(username string) (*domain.UserData, error) {
	userData := domain.UserData{}
	selectStatement := `SELECT * FROM users where username=$1`
	row := p.conn.QueryRow(p.ctx, selectStatement, username)
	err := row.Scan(&userData.UserName, &userData.Password, &userData.Email, &userData.FullName,
		&userData.NrDeployedApps, &userData.JobRole, &userData.BirthDate, &userData.JoinedDate, &userData.LastTimeOnline,
		&userData.WantNotify, &userData.Applications, &userData.UserLocked, &userData.UserTimeout,
		&userData.UserLimitLoginAttempts, &userData.UserLimitTimeout, &userData.UserID, &userData.Role, &userData.OTPData.OTPEnabled,
		&userData.OTPData.OTPVerified, &userData.OTPData.OTPSecret, &userData.OTPData.OTPAuthURL)
	if err != nil {
		p.psqlLogger.Error(" could not retrieve user", zap.Error(err))
		return nil, err
	}
	p.psqlLogger.Info("Successfuly retrieved user", zap.Any("user_data", userData))
	return &userData, nil
}

// GetUserDataWithUUID retrieves user using UUID for authorization from PostgreSql table
func (p *PostgreSqlRepo) GetUserDataWithUUID(userID string) (*domain.UserData, error) {
	userData := domain.UserData{}
	selectStatement := `SELECT username,email,user_id,role, applications,user_locked,user_timeout, 
						user_limit_login_attempts, user_limit_timeout,otp_secret FROM users where user_id=$1`

	row := p.conn.QueryRow(p.ctx, selectStatement, userID)
	err := row.Scan(&userData.UserName, &userData.Email, &userData.UserID, &userData.Role, &userData.Applications, &userData.UserLocked,
		&userData.UserTimeout, &userData.UserLimitLoginAttempts, &userData.UserLimitTimeout, &userData.OTPData.OTPSecret)
	if err != nil {
		p.psqlLogger.Error(" could not retrieve user using uuid", zap.Error(err))
		return nil, err
	}
	p.psqlLogger.Info("Successfuly retrieved user", zap.String("user_name", userData.UserName))
	return &userData, nil
}

// GetUserDataWitEmail retrieves user using Email for authorization from PostgreSql table
func (p *PostgreSqlRepo) GetUserDataWithEmail(email string) (*domain.UserData, error) {
	userData := domain.UserData{}
	selectStatement := `SELECT username,user_id,role, applications,user_locked,user_timeout, 
					user_limit_login_attempts, user_limit_timeout  FROM users where email=$1`

	row := p.conn.QueryRow(p.ctx, selectStatement, email)
	err := row.Scan(&userData.UserName, &userData.UserID, &userData.Role, &userData.Applications, &userData.UserLocked,
		&userData.UserTimeout, &userData.UserLimitLoginAttempts, &userData.UserLimitTimeout)
	if err != nil {
		p.psqlLogger.Error(" could not retrieve user using email", zap.Error(err))
		return nil, err
	}
	p.psqlLogger.Info("Successfuly retrieved user", zap.String("user_name", userData.UserName))
	return &userData, nil
}

// UpdateUserData updates user from PostgreSql table
func (p *PostgreSqlRepo) UpdateUserData(userData *domain.UserData) error {
	if userData.Password != "" {
		userData.Password = helpers.HashPassword(userData.Password)
	}
	updateStatement := `UPDATE  users SET 
						nr_deployed_apps=$1,
						job_role = COALESCE(NULLIF($2,E''),job_role),
						email=COALESCE(NULLIF($3,E''), email),
						want_notify=COALESCE(NULLIF($4,FALSE), want_notify), 
						password=COALESCE(NULLIF($5,E''), password),
						birth_date=COALESCE(NULLIF($6,E''), birth_date),
						full_name=COALESCE(NULLIF($7,E''), full_name),
						user_locked=COALESCE(NULLIF($8,FALSE), user_locked),
						user_timeout=$9,
						user_limit_login_attempts = $10,
						user_limit_timeout = $11
						WHERE username=$12`

	row, err := p.conn.Exec(p.ctx, updateStatement, userData.NrDeployedApps, userData.JobRole, userData.Email,
		userData.WantNotify, userData.Password, userData.BirthDate, userData.FullName, userData.UserLocked, userData.UserTimeout,
		userData.UserLimitLoginAttempts, userData.UserLimitTimeout, userData.UserName)
	if err != nil {
		p.psqlLogger.Error(" could not update user", zap.Error(err))
		return err
	}
	if row.RowsAffected() != 1 {
		p.psqlLogger.Error(" no row found to update")
		return errors.New("no row found to update")
	}
	p.psqlLogger.Info("Successfuly updated user", zap.String("user_name", userData.UserName))
	return nil
}

// UpdateUserLastTimeOnlineData updates timestamp of last time online from PostgreSql table
func (p *PostgreSqlRepo) UpdateUserLastTimeOnlineData(lastTimestamp time.Time, userData *domain.UserData) error {
	updateStatement := "UPDATE  users SET last_time_online=$1 WHERE username=$2"

	row, err := p.conn.Exec(p.ctx, updateStatement, lastTimestamp, userData.UserName)
	if err != nil {
		p.psqlLogger.Error(" could not update user last time online", zap.Error(err))
		return err
	}
	if row.RowsAffected() != 1 {
		p.psqlLogger.Error(" no row found to update")
		return errors.New("no row found to update")
	}
	p.psqlLogger.Info("Successfuly updated user last timestamp", zap.String("user_last_timestamp", lastTimestamp.String()))
	return nil
}

// UpdateUserOTP updates otp user data from PostgreSql table
func (p *PostgreSqlRepo) UpdateUserOTP(otpData domain.OneTimePassData, userData *domain.UserData) error {
	updateStatement := `UPDATE  users SET 
						otp_enabled=$1,
						otp_verified=$2,
						otp_secret=$3,
						otp_auth_url=$4 
						WHERE username=$5`

	row, err := p.conn.Exec(p.ctx, updateStatement, otpData.OTPEnabled, otpData.OTPVerified, otpData.OTPSecret, otpData.OTPAuthURL, userData.UserName)
	if err != nil {
		p.psqlLogger.Error(" could not update user otp", zap.Error(err))
		return err
	}
	if row.RowsAffected() != 1 {
		p.psqlLogger.Error(" no row found to update")
		return errors.New("no row found to update")
	}
	p.psqlLogger.Info("Successfuly updated user otp", zap.Any("user_otp", otpData))
	return nil
}

// UpdateUserRoleData updates user role from PostgreSql table
func (p *PostgreSqlRepo) UpdateUserRoleData(role, userID string, userData *domain.UserData) error {
	updateStatement := "UPDATE  users SET role=$1, user_id=$2 WHERE username=$3"

	row, err := p.conn.Exec(p.ctx, updateStatement, role, userID, userData.UserName)
	if err != nil {
		p.psqlLogger.Error(" could not update user role\n", zap.Error(err))
		return err
	}
	if row.RowsAffected() != 1 {
		p.psqlLogger.Error(" no row found to update")
		return errors.New("no row found to update")
	}
	p.psqlLogger.Info("Successfuly updated user role", zap.String("user_role", role))
	return nil
}

// UpdateUserAppsData updates user apps from PostgreSql table
func (p *PostgreSqlRepo) UpdateUserAppsData(appName, userName string) error {
	updateStatement := "UPDATE users SET applications=array_append(applications, $1) WHERE username=$2"

	row, err := p.conn.Exec(p.ctx, updateStatement, appName, userName)
	if err != nil {
		p.psqlLogger.Error(" could not update user with the new app", zap.String("user_name", userName), zap.String("app_name", appName), zap.Error(err))
		return err
	}
	if row.RowsAffected() != 1 {
		p.psqlLogger.Error(" no row found to update")
		return errors.New("no row found to update")
	}
	p.psqlLogger.Info("Successfuly updated user apps", zap.String("updated_app", appName))
	return nil
}

// DeleteUserAppsData deletes user app from PostgreSql table
func (p *PostgreSqlRepo) DeleteUserAppsData(appName, userName string) error {
	updateStatement := "UPDATE users SET applications=array_remove(applications, $1) WHERE username=$2"

	row, err := p.conn.Exec(p.ctx, updateStatement, appName, userName)
	if err != nil {
		p.psqlLogger.Error(" could not update user without app", zap.String("user_name", userName), zap.String("app_name", appName), zap.Error(err))
		return err
	}
	if row.RowsAffected() != 1 {
		p.psqlLogger.Error(" no row found to update")
		return errors.New("no row found to update")
	}
	p.psqlLogger.Info("Successfuly updated user apps(delete)", zap.String("deleted_app", appName))
	return nil
}

// DeleteUserData deletes user from PostgreSql table
func (p *PostgreSqlRepo) DeleteUserData(username string) error {
	deleteStatement := "DELETE FROM users WHERE username=$1"

	row, err := p.conn.Exec(p.ctx, deleteStatement, username)
	if err != nil {
		p.psqlLogger.Error(" could not delete data", zap.Error(err))
		return err
	}
	if row.RowsAffected() != 1 {
		p.psqlLogger.Error(" no row found to delete")
		return errors.New("no row found to delete")
	}
	p.psqlLogger.Info("Successfuly deleted user", zap.String("deleted_user", username))
	return nil
}

// InsertAppData inserts app in PostgreSql table
func (p *PostgreSqlRepo) InsertAppData(appData *domain.ApplicationData) error {
	newApplicationData := domain.ApplicationData{}
	insertStatement := `INSERT INTO apps (name, description, is_running, created_timestamp, updated_timestamp,flag_arguments, 
						param_arguments,is_main,subgroup_files, owner, namespace, schedule_type, port, ip_address,alert_ids) 
						VALUES ($1, $2, $3, $4, $5, $6 ,$7, $8, $9, $10, $11, $12, $13, $14,$15) 
						RETURNING name`
	row := p.conn.QueryRow(p.ctx, insertStatement, appData.Name, zeronull.Text(appData.Description), appData.IsRunning, appData.CreatedTimestamp,
		appData.UpdatedTimestamp, zeronull.Text(appData.FlagArguments), zeronull.Text(appData.ParamArguments), appData.IsMain, appData.SubgroupFiles,
		appData.Owner, zeronull.Text(appData.Namespace), zeronull.Text(appData.ScheduleType), zeronull.Int8(int64(*appData.Port)),
		zeronull.Text(*appData.IpAddress), appData.AlertIDs)
	err := row.Scan(&newApplicationData.Name)
	if err != nil {
		p.psqlLogger.Error(" could not insert app", zap.Error(err))
		return err
	}
	p.psqlLogger.Info("Successfuly inserted app", zap.String("new_app", newApplicationData.Name))
	return nil
}

// GetAllApps retrieves all apps from db
func (p *PostgreSqlRepo) GetAllApps() ([]*domain.ApplicationData, error) {

	applicationsData := make([]*domain.ApplicationData, 0)
	selectStatement := `SELECT name,COALESCE(description, '') as description, is_running, created_timestamp, updated_timestamp, 
						COALESCE(flag_arguments, '') as flag_arguments, 
						COALESCE(param_arguments, '') as param_arguments,
						is_main,subgroup_files,owner,
						COALESCE(namespace, '') as namespace,
						COALESCE(schedule_type, '') as schedule_type,
						COALESCE(port, 0) as port, 
						COALESCE(ip_address, '') as ip_address,
						alert_ids FROM apps`

	rows, err := p.conn.Query(p.ctx, selectStatement)
	if err != nil {
		p.psqlLogger.Error(" could not retrieve all apps", zap.Error(err))
		return nil, err
	}

	for rows.Next() {
		applicationData := &domain.ApplicationData{}
		err := rows.Scan(&applicationData.Name, &applicationData.Description, &applicationData.IsRunning,
			&applicationData.CreatedTimestamp, &applicationData.UpdatedTimestamp, &applicationData.FlagArguments, &applicationData.ParamArguments,
			&applicationData.IsMain, &applicationData.SubgroupFiles, &applicationData.Owner, &applicationData.Namespace, &applicationData.ScheduleType,
			&applicationData.Port, &applicationData.IpAddress, &applicationData.AlertIDs)
		if err != nil {
			p.psqlLogger.Error(" could not scan app", zap.Error(err))
			return nil, err
		}
		applicationsData = append(applicationsData, applicationData)
	}
	return applicationsData, nil

}

// GetAppsCount retrieves apps count from db
func (p *PostgreSqlRepo) GetAppsCount(owner string, countApp bool) (int, error) {
	var totals int
	psqlArguments := make(pgx.NamedArgs, 0)
	selectStatement := "SELECT COUNT(*) FROM apps WHERE"
	if owner != "" {
		selectStatement += " owner=@app_owner AND is_main=TRUE"
		if countApp {
			selectStatement += " AND is_running=TRUE"
		}
		psqlArguments["app_owner"] = owner
	} else {
		if countApp {
			selectStatement += " is_running=TRUE AND"
		}
		selectStatement += " is_main=TRUE"
	}

	row := p.conn.QueryRow(p.ctx, selectStatement, psqlArguments)
	err := row.Scan(&totals)
	if err != nil {
		p.psqlLogger.Error(" could not retrieve apps count", zap.Error(err))
		return 0, err
	}

	return totals, nil

}

// GetAppsData retrieves apps from PostgreSql table using fql filter
func (p *PostgreSqlRepo) GetAppsData(owner, filterConditions, limit, offset string, sortParams []string) (int, int, []*domain.ApplicationData, error) {
	totals, _ := p.GetAppsCount(owner, false)
	resultsCount := 0

	applicationsData := make([]*domain.ApplicationData, 0)
	var selectStatement string
	var err error
	var rows pgx.Rows
	filterArguments := make(pgx.NamedArgs, 0)
	//Parse fql filter
	filters, err := helpers.ParseFQLFilter(filterConditions, p.psqlLogger)
	if err != nil {
		return 0, 0, nil, err
	}
	if len(filters) > 0 && len(filters[0]) >= 3 {
		selectStatement := `SELECT name,COALESCE(description, '') as description, is_running, created_timestamp, updated_timestamp, 
							COALESCE(flag_arguments, '') as flag_arguments, 
							COALESCE(param_arguments, '') as param_arguments,
							is_main,subgroup_files,owner,
							COALESCE(namespace, '') as namespace,
						    COALESCE(schedule_type, '') as schedule_type,
							COALESCE(port, 0) as port, 
							COALESCE(ip_address, '') as ip_address,
							alert_ids FROM apps where (`
		for i, filterParams := range filters {
			if len(filterParams) == 3 {
				filterParams[2] = strings.ReplaceAll(filterParams[2], `"`, "")
				paramID := helpers.GetRandomInt()
				if filterParams[0] == "kname" {

					knamePostgresID := filterParams[0] + strconv.Itoa(paramID)
					if filterParams[1] == "!=" {
						selectStatement += "name NOT ILIKE @" + knamePostgresID
					} else {
						selectStatement += "name ILIKE  @" + knamePostgresID
					}
					filterArguments[knamePostgresID] = "%" + filterParams[2] + "%"

				} else if filterParams[0] == "description" || filterParams[0] == "ip_address" || filterParams[0] == "schedule_type" {
					descriptionPostgresID := filterParams[0] + strconv.Itoa(paramID)
					if filterParams[1] == "!=" {
						if filterParams[2] == "NULL" {
							selectStatement += "(" + filterParams[0] + " NOT ILIKE @" + descriptionPostgresID + " OR " + filterParams[0] + " IS NOT NULL)"
						} else {
							selectStatement += filterParams[0] + " NOT ILIKE @" + descriptionPostgresID
						}

					} else {
						if filterParams[2] == "NULL" {
							selectStatement += "(" + filterParams[0] + " ILIKE @" + descriptionPostgresID + " OR " + filterParams[0] + " IS NULL)"
						} else {
							selectStatement += filterParams[0] + " ILIKE @" + descriptionPostgresID
						}
					}
					filterArguments[descriptionPostgresID] = "%" + filterParams[2] + "%"

				} else if filterParams[0] == "created_timestamp" || filterParams[0] == "updated_timestamp" {
					timestampPostgresID := filterParams[0] + strconv.Itoa(paramID)
					if filterParams[1] == "!=" {
						selectStatement += filterParams[0] + " != current_timestamp - @" + timestampPostgresID + " :: interval"
					} else if filterParams[1] == ">" {
						selectStatement += filterParams[0] + " > current_timestamp - @" + timestampPostgresID + " :: interval"
					} else if filterParams[1] == "=" {
						selectStatement += filterParams[0] + " = current_timestamp - @" + timestampPostgresID + " :: interval"
					} else if filterParams[1] == "<" {
						selectStatement += filterParams[0] + " < current_timestamp -  @" + timestampPostgresID + " :: interval"
					} else if filterParams[1] == "<=" {
						selectStatement += filterParams[0] + " <= current_timestamp - @" + timestampPostgresID + " :: interval"
					} else {
						selectStatement += filterParams[0] + " >= current_timestamp - @" + timestampPostgresID + " :: interval"
					}
					filterArguments[timestampPostgresID] = "%" + filterParams[2] + "%"

				} else if filterParams[0] == "port" {
					portID := filterParams[0] + strconv.Itoa(paramID)
					if filterParams[1] == "!=" {
						if filterParams[2] == "NULL" {
							selectStatement += filterParams[0] + " IS NOT NULL"
						} else {
							selectStatement += filterParams[0] + " != @" + portID
						}
					} else if filterParams[1] == "=" {
						if filterParams[2] == "NULL" {
							selectStatement += filterParams[0] + " IS NULL"
						} else {
							selectStatement += filterParams[0] + " = @" + portID
						}
					} else if filterParams[1] == ">" {
						selectStatement += filterParams[0] + " > @" + portID
					} else if filterParams[1] == ">=" {
						selectStatement += filterParams[0] + " >= @" + portID
					} else if filterParams[1] == "<" {
						selectStatement += filterParams[0] + " < @" + portID
					} else if filterParams[1] == "<=" {
						selectStatement += filterParams[0] + " <= @" + portID
					}
					filterArguments[portID] = filterParams[2]
				} else {
					selectStatement += filterParams[0] + "=@is_running"
					filterArguments["is_running"] = filterParams[2]

				}
			} else if len(filterParams) == 2 || len(filterParams) > 4 {
				p.psqlLogger.Error(" Invalid filter", zap.Any("filter_params", filterParams))
				return 0, 0, nil, fmt.Errorf("invalid fql filter")
			}

			if i != len(filters)-1 && len(filterParams) == 1 {
				if filterParams[0] == "&&" {
					selectStatement += " AND "
				} else if filterParams[0] == "||" {
					selectStatement += " OR "
				}

			}
			if i != len(filters)-1 && len(filterParams) == 0 {
				selectStatement += ") AND owner=@app_owner"
				if len(sortParams) == 2 {
					selectStatement += " ORDER BY " + sortParams[0] + " " + sortParams[1]
				}
				if offset != "" {
					selectStatement += " OFFSET " + offset + " "
				}
				if limit != "" {
					selectStatement += " LIMIT " + limit + " "
				}
				filterArguments["app_owner"] = owner
				break
			}

		}
		p.psqlLogger.Info(selectStatement)
		rows, err = p.conn.Query(p.ctx, selectStatement, filterArguments)
		if err != nil {
			p.psqlLogger.Error(" could not retrieve app", zap.Error(err))
			return 0, 0, nil, err
		}

	} else {
		selectStatement = `SELECT name,COALESCE(description, '') as description, is_running, created_timestamp, updated_timestamp, 
						COALESCE(flag_arguments, '') as flag_arguments, 
						COALESCE(param_arguments, '') as param_arguments,
						is_main,subgroup_files,owner,
						COALESCE(namespace, '') as namespace,
						COALESCE(schedule_type, '') as schedule_type,
						COALESCE(port, 0) as port, 
						COALESCE(ip_address, '') as ip_address,
						alert_ids from  apps where owner=$1 `
		if len(sortParams) == 2 {
			selectStatement += "ORDER BY " + sortParams[0] + " " + sortParams[1]
		}
		if offset != "" {
			selectStatement += " OFFSET " + offset + " "
		}
		if limit != "" {
			selectStatement += " LIMIT " + limit + " "
		}
		p.psqlLogger.Info(selectStatement)
		rows, err = p.conn.Query(p.ctx, selectStatement, owner)
		if err != nil {
			p.psqlLogger.Error(" could not retrieve apps", zap.Error(err))
			return 0, 0, nil, err
		}
	}

	for rows.Next() {
		applicationData := &domain.ApplicationData{}
		err := rows.Scan(&applicationData.Name, &applicationData.Description, &applicationData.IsRunning,
			&applicationData.CreatedTimestamp, &applicationData.UpdatedTimestamp, &applicationData.FlagArguments, &applicationData.ParamArguments,
			&applicationData.IsMain, &applicationData.SubgroupFiles, &applicationData.Owner, &applicationData.Namespace, &applicationData.ScheduleType,
			&applicationData.Port, &applicationData.IpAddress, &applicationData.AlertIDs)
		if err != nil {
			p.psqlLogger.Error(" could not scan app", zap.Error(err))
			return 0, 0, nil, err
		}
		applicationsData = append(applicationsData, applicationData)
	}

	p.psqlLogger.Info("Successfuly retrieved apps", zap.Any("app_data", applicationsData))
	resultsCount = len(applicationsData)
	return totals, resultsCount, applicationsData, nil
}

// UpdateAppData updates app from PostgreSql table
func (p *PostgreSqlRepo) UpdateAppData(appData *domain.ApplicationData) error {
	updateStatement := `UPDATE  apps SET 
						description=COALESCE(NULLIF($1,E''), description), 
						is_running=COALESCE(NULLIF($2,FALSE), is_running),
						updated_timestamp=$3,
						flag_arguments=COALESCE(NULLIF($4,E''), flag_arguments),
						param_arguments=COALESCE(NULLIF($5,E''), param_arguments),
						namespace=COALESCE(NULLIF($6,E''), namespace),
						schedule_type=COALESCE(NULLIF($7,E''), schedule_type),
						port=COALESCE(NULLIF($8,0), port),
						ip_address=COALESCE(NULLIF($9,E''), ip_address),
						alert_ids=$10
						WHERE name=$11`

	row, err := p.conn.Exec(p.ctx, updateStatement, appData.Description, appData.IsRunning, appData.UpdatedTimestamp,
		appData.FlagArguments, appData.ParamArguments, appData.Namespace, appData.ScheduleType, zeronull.Int8(int64(*appData.Port)),
		zeronull.Text(*appData.IpAddress), appData.AlertIDs, appData.Name)
	if err != nil {
		p.psqlLogger.Error(" could not update app ", zap.Error(err))
		return err
	}
	if row.RowsAffected() != 1 {
		p.psqlLogger.Error(" no row found to update")
		return errors.New("no row found to update")
	}
	p.psqlLogger.Info("Successfuly updated app", zap.String("updated_app", appData.Name))
	return nil
}

// UpdateAppAlertID updates app by adding alert_id
func (p *PostgreSqlRepo) UpdateAppAlertID(appName, alertID string) error {
	updateStatement := "UPDATE apps SET alert_ids=array_append(alert_ids, $1)  WHERE name=$2"

	row, err := p.conn.Exec(p.ctx, updateStatement, alertID, appName)
	if err != nil {
		p.psqlLogger.Error(" could not update remove alert", zap.String("app_name", appName), zap.Error(err))
		return err
	}
	if row.RowsAffected() != 1 {
		p.psqlLogger.Error(" no row found to update")
		return errors.New("no row found to update")
	}
	p.psqlLogger.Info("Successfuly updated alert_id", zap.String("updated_app", appName))
	return nil
}

// RemoveAppAlertID updates app by removing alert_id
func (p *PostgreSqlRepo) RemoveAppAlertID(alertUID, appName string) error {
	updateStatement := "UPDATE apps SET alert_ids=array_remove(alert_ids,$1) WHERE name=$2"

	row, err := p.conn.Exec(p.ctx, updateStatement, alertUID, appName)
	if err != nil {
		p.psqlLogger.Error(" could not update remove alert", zap.String("app_name", appName), zap.Error(err))
		return err
	}
	if row.RowsAffected() != 1 {
		p.psqlLogger.Error(" no row found to update")
		return errors.New("no row found to update")
	}
	p.psqlLogger.Info("Successfuly removed alert_id", zap.String("updated_app", appName))
	return nil
}

// DeleteAppData deletes app from PostgreSql table
func (p *PostgreSqlRepo) DeleteAppData(appName, userName string) error {
	updateStatement := "UPDATE  users SET applications=array_remove(applications, $1) WHERE username=$2"

	row, err := p.conn.Exec(p.ctx, updateStatement, appName, userName)
	if err != nil {
		p.psqlLogger.Error(" could not remove app from user", zap.String("app_name", appName), zap.String("user_name", userName), zap.Error(err))
		return err
	}
	if row.RowsAffected() != 1 {
		p.psqlLogger.Error(" no row found to update")
		return errors.New("no row found to update")
	}
	deleteStatement := "DELETE FROM apps WHERE name = $1"

	row, err = p.conn.Exec(p.ctx, deleteStatement, appName)
	if err != nil {
		p.psqlLogger.Error(" could not delete app", zap.String("app_name", appName), zap.Error(err))
		return err
	}
	if row.RowsAffected() != 1 {
		p.psqlLogger.Error(" no row found to delete")
		return errors.New("no row found to delete")
	}

	p.psqlLogger.Info("Successfuly deleted user app", zap.String("deleted_app", appName))
	return nil
}

// InsertFormData inserts form in db
func (p *PostgreSqlRepo) InsertFormData(formData *domain.FormData) (int, error) {
	newFormData := domain.FormData{}
	insertStatement := `INSERT INTO forms (bad_features,project_like_rate,friends_recommend_rate, project_issues,
						project_has_issues,project_suggestions, good_features) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`

	row := p.conn.QueryRow(p.ctx, insertStatement, formData.BadFeatures, formData.ProjectLikeRate, formData.FriendsRecommendRate, formData.ProjectIssues,
		formData.ProjectHasIssues, formData.ProjectSuggestions, formData.GoodFeatures)
	err := row.Scan(&newFormData.ID)
	if err != nil {
		p.psqlLogger.Error(" could not insert data", zap.Error(err))
		return 0, err
	}
	p.psqlLogger.Info("Successfuly inserted form", zap.Any("form_id", newFormData.ID))
	return newFormData.ID, nil
}

// GetFormStatistics retrieves aggregates for all entries in form table
func (p *PostgreSqlRepo) GetFormStatistics() (*domain.FormStatistics, error) {
	formStats := domain.FormStatistics{}
	statisticsStatement := `SELECT ROUND(AVG(project_like_rate::DECIMAL),3) AS avg_project_like_rate, 
							ROUND(AVG(friends_recommend_rate::DECIMAL),3) AS avg_friends_recommend_rate,
							string_to_array(string_agg(bad_features,chr(10)), chr(10)) AS total_bad_features,
							string_to_array(string_agg(good_features,chr(10)), chr(10)) AS total_good_features,
							string_to_array(string_agg(project_suggestions,chr(10)), chr(10)) AS total_project_suggestions,
							string_to_array(string_agg(project_issues,chr(10)), chr(10)) AS total_project_issues
							FROM forms;`
	row := p.conn.QueryRow(p.ctx, statisticsStatement)
	err := row.Scan(&formStats.AverageProjectLikeRate, &formStats.AverageFriendsRecommendRate, &formStats.TotalBadFeatures,
		&formStats.TotalGoodFeatures, &formStats.TotalProjectSuggestions, &formStats.TotalProjectIssues)
	if err != nil {
		p.psqlLogger.Error(" could not retrieve form stats data", zap.Error(err))
		return nil, err
	}
	return &formStats, nil
}
