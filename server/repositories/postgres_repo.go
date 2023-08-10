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
						birth_date, joined_date, last_time_online, want_notify,applications,user_id, role) 
						VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING username`

	row := p.conn.QueryRow(p.ctx, insertStatement, userData.UserName, userData.Password, userData.Email,
		userData.FullName, userData.NrDeployedApps, userData.JobRole, userData.BirthDate, userData.JoinedDate, userData.LastTimeOnline,
		userData.WantNotify, userData.Applications, userData.UserID, userData.Role)
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
		&userData.WantNotify, &userData.Applications, &userData.UserID, &userData.Role)
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
	selectStatement := "SELECT username,user_id,role, applications FROM users where user_id=$1"

	row := p.conn.QueryRow(p.ctx, selectStatement, userID)
	err := row.Scan(&userData.UserName, &userData.UserID, &userData.Role, &userData.Applications)
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
	selectStatement := "SELECT username,user_id,role, applications FROM users where email=$1"

	row := p.conn.QueryRow(p.ctx, selectStatement, email)
	err := row.Scan(&userData.UserName, &userData.UserID, &userData.Role, &userData.Applications)
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
						nr_deployed_apps= $1,
						job_role = COALESCE(NULLIF($2,E''),job_role),
						email=COALESCE(NULLIF($3,E''), email),
						want_notify=COALESCE(NULLIF($4,E''), want_notify), 
						password=COALESCE(NULLIF($5,E''), password),
						birth_date=COALESCE(NULLIF($6,E''), birth_date),
						full_name=COALESCE(NULLIF($7,E''), full_name)
						WHERE username=$8`

	row, err := p.conn.Exec(p.ctx, updateStatement, userData.NrDeployedApps, userData.JobRole, userData.Email,
		userData.WantNotify, userData.Password, userData.BirthDate, userData.FullName, userData.UserName)
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
	insertStatement := "INSERT INTO apps (name, description, is_running, created_timestamp, updated_timestamp) VALUES ($1, $2, $3, $4, $5) RETURNING name"
	row := p.conn.QueryRow(p.ctx, insertStatement, appData.Name, zeronull.Text(appData.Description), appData.IsRunning, appData.CreatedTimestamp, appData.UpdatedTimestamp)
	err := row.Scan(&newApplicationData.Name)
	if err != nil {
		p.psqlLogger.Error(" could not insert app", zap.Error(err))
		return err
	}
	p.psqlLogger.Info("Successfuly inserted app", zap.String("new_app", newApplicationData.Name))
	return nil
}

// GetAppsData retrieves apps from PostgreSql table using fql filter
func (p *PostgreSqlRepo) GetAppsData(appname, filterConditions string) ([]*domain.ApplicationData, error) {
	applicationsData := make([]*domain.ApplicationData, 0)
	var selectStatement string
	var err error
	var rows pgx.Rows
	filterArguments := make(pgx.NamedArgs, 0)
	//Parse fql filter
	filters := helpers.ParseFQLFilter(filterConditions, p.psqlLogger)
	if filters == nil {
		return nil, fmt.Errorf("could not parse fql filter")
	}
	if len(filters) > 0 && len(filters[0]) >= 3 {
		selectStatement := "SELECT name,COALESCE(description, '') as description, is_running, created_timestamp, updated_timestamp FROM apps where ("
		for i, filterParams := range filters {
			if len(filterParams) == 3 {
				filterParams[2] = strings.ReplaceAll(filterParams[2], `"`, "")
				paramID := helpers.GetRandomInt()
				if filterParams[0] == "kname" {

					knamePostgresID := filterParams[0] + strconv.Itoa(paramID)
					if filterParams[1] == "!=" {
						selectStatement += "name NOT ILIKE @" + knamePostgresID
						filterArguments[knamePostgresID] = "%" + filterParams[2] + "%"
					} else {
						selectStatement += "name ILIKE  @" + knamePostgresID
						filterArguments[knamePostgresID] = "%" + filterParams[2] + "%"
					}

				} else if filterParams[0] == "description" {
					descriptionPostgresID := filterParams[0] + strconv.Itoa(paramID)
					if filterParams[1] == "!=" {
						if filterParams[2] == "NULL" {
							selectStatement += "(" + filterParams[0] + " NOT ILIKE @" + descriptionPostgresID + " OR description IS NOT NULL)"
						} else {
							selectStatement += filterParams[0] + " NOT ILIKE @" + descriptionPostgresID
						}

						filterArguments[descriptionPostgresID] = "%" + filterParams[2] + "%"
					} else {
						if filterParams[2] == "NULL" {
							selectStatement += "(" + filterParams[0] + " ILIKE @" + descriptionPostgresID + " OR description IS NULL)"
						} else {
							selectStatement += filterParams[0] + " ILIKE @" + descriptionPostgresID
						}

						filterArguments[descriptionPostgresID] = "%" + filterParams[2] + "%"
					}

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

				} else {
					selectStatement += filterParams[0] + "=@is_running"
					filterArguments["is_running"] = filterParams[2]

				}
			} else if len(filterParams) == 2 || len(filterParams) > 4 {
				p.psqlLogger.Error(" Invalid filter", zap.Any("filter_params", filterParams))
				return nil, fmt.Errorf("invalid fql filter")
			}

			if i != len(filters)-1 && len(filterParams) == 1 {
				if filterParams[0] == "&&" {
					selectStatement += " AND "
				} else if filterParams[0] == "||" {
					selectStatement += " OR "
				}

			}
			if i != len(filters)-1 && len(filterParams) == 0 {
				selectStatement += ") AND name=@app_name1"

				filterArguments["app_name1"] = appname
				break
			}

		}
		p.psqlLogger.Info(selectStatement)
		rows, err = p.conn.Query(p.ctx, selectStatement, filterArguments)
		if err != nil {
			p.psqlLogger.Error(" could not retrieve app", zap.Error(err))
			return nil, err
		}

	} else {
		selectStatement = "SELECT name,COALESCE(description, '') as description, is_running, created_timestamp, updated_timestamp FROM apps where name=$1"
		p.psqlLogger.Info(selectStatement)
		rows, err = p.conn.Query(p.ctx, selectStatement, appname)
		if err != nil {
			p.psqlLogger.Error(" could not retrieve appn", zap.Error(err))
			return nil, err
		}
	}

	for rows.Next() {
		applicationData := &domain.ApplicationData{}
		err := rows.Scan(&applicationData.Name, &applicationData.Description, &applicationData.IsRunning,
			&applicationData.CreatedTimestamp, &applicationData.UpdatedTimestamp)
		if err != nil {
			p.psqlLogger.Error(" could not scan app", zap.Error(err))
			return nil, err
		}
		applicationsData = append(applicationsData, applicationData)
	}

	p.psqlLogger.Info("Successfuly retrieved apps", zap.Any("app_data", applicationsData))
	return applicationsData, nil
}

// UpdateAppData updates app from PostgreSql table
func (p *PostgreSqlRepo) UpdateAppData(appData *domain.ApplicationData) error {
	updateStatement := `UPDATE  apps SET 
						description=COALESCE(NULLIF($1,E''), description), 
						is_running=COALESCE(NULLIF($2,E''), is_running),
						updated_timestamp=$3 
						WHERE name=$4`

	row, err := p.conn.Exec(p.ctx, updateStatement, appData.Description, appData.IsRunning, appData.UpdatedTimestamp, appData.Name)
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
