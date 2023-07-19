package repositories

import (
	"cloudadmin/domain"
	"cloudadmin/helpers"
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sirupsen/logrus"
)

// PostgresSqlRepo represents info about PostgreSql
type PostgreSqlRepo struct {
	ctx        context.Context
	conn       *pgxpool.Pool
	psqlLogger *logrus.Logger
}

// NewPostgreSqlRepo returns a new PostgreSql repo
func NewPostgreSqlRepo(ctx context.Context, username, password, host, databaseName string, port int, logger *logrus.Logger) *PostgreSqlRepo {
	url := fmt.Sprintf("postgres://%s:%s@%s:%d/%s", username, password, host, port, databaseName)

	dbPool, err := pgxpool.New(ctx, url)
	if err != nil {
		logger.Printf("[ERROR] could not connect to database : %v\n", err)
		return nil
	}

	// check connection
	err = dbPool.Ping(ctx)
	if err != nil {
		logger.Printf("[ERROR] could not ping : %v\n", err)
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
		p.psqlLogger.Errorf("[ERROR] could not insert data with error : %v\n", err)
		return err
	}
	p.psqlLogger.Printf("Successfuly inserted user : %+v", newUserData.UserName)
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
		p.psqlLogger.Errorf("[ERROR] could not retrieve user with error : %v\n", err)
		return nil, err
	}
	p.psqlLogger.Printf("Successfuly retrieved user : %+v", userData)
	return &userData, nil
}

func (p *PostgreSqlRepo) GetUserDataWithUUID(userID string) (*domain.UserData, error) {
	userData := domain.UserData{}
	selectStatement := "SELECT username,user_id,role, applications FROM users where user_id=$1"

	row := p.conn.QueryRow(p.ctx, selectStatement, userID)
	err := row.Scan(&userData.UserName, &userData.UserID, &userData.Role, &userData.Applications)
	if err != nil {
		p.psqlLogger.Errorf("[ERROR] could not retrieve user using uuid with error : %v\n", err)
		return nil, err
	}
	p.psqlLogger.Printf("Successfuly retrieved user : %+v", userData.UserName)
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
		p.psqlLogger.Errorf("[ERROR] could not update user with error : %v\n", err)
		return err
	}
	if row.RowsAffected() != 1 {
		p.psqlLogger.Errorf("[ERROR] no row found to update")
		return errors.New("no row found to update")
	}
	p.psqlLogger.Printf("Successfuly updated user : %+v", userData.UserName)
	return nil
}

// UpdateUserLastTimeOnlineData updates timestamp of last time online from PostgreSql table
func (p *PostgreSqlRepo) UpdateUserLastTimeOnlineData(lastTimestamp time.Time, userData *domain.UserData) error {
	updateStatement := "UPDATE  users SET last_time_online=$1 WHERE username=$2"

	row, err := p.conn.Exec(p.ctx, updateStatement, lastTimestamp, userData.UserName)
	if err != nil {
		p.psqlLogger.Errorf("[ERROR] could not update user last time online with error : %v\n", err)
		return err
	}
	if row.RowsAffected() != 1 {
		p.psqlLogger.Errorf("[ERROR] no row found to update")
		return errors.New("no row found to update")
	}
	p.psqlLogger.Printf("Successfuly updated user last timestamp with : %v", lastTimestamp.String())
	return nil
}

// UpdateUserRoleData updates user role from PostgreSql table
func (p *PostgreSqlRepo) UpdateUserRoleData(role, userID string, userData *domain.UserData) error {
	updateStatement := "UPDATE  users SET role=$1, user_id=$2 WHERE username=$3"

	row, err := p.conn.Exec(p.ctx, updateStatement, role, userID, userData.UserName)
	if err != nil {
		p.psqlLogger.Errorf("[ERROR] could not update user role with error : %v\n", err)
		return err
	}
	if row.RowsAffected() != 1 {
		p.psqlLogger.Errorf("[ERROR] no row found to update")
		return errors.New("no row found to update")
	}
	p.psqlLogger.Printf("Successfuly updated user role with : %v", role)
	return nil
}

// UpdateUserAppsData updates user apps from PostgreSql table
func (p *PostgreSqlRepo) UpdateUserAppsData(appName, userName string) error {
	updateStatement := "UPDATE users SET applications=array_append(applications, $1) WHERE username=$2"

	row, err := p.conn.Exec(p.ctx, updateStatement, appName, userName)
	if err != nil {
		p.psqlLogger.Errorf("[ERROR] could not update user: %v with the new app : %v  with error : %v\n", userName, appName, err)
		return err
	}
	if row.RowsAffected() != 1 {
		p.psqlLogger.Errorf("[ERROR] no row found to update")
		return errors.New("no row found to update")
	}
	p.psqlLogger.Printf("Successfuly updated user apps with : %+v", appName)
	return nil
}

// DeleteUserData deletes user from PostgreSql table
func (p *PostgreSqlRepo) DeleteUserData(username string) error {
	deleteStatement := "DELETE FROM users WHERE username=$1"

	row, err := p.conn.Exec(p.ctx, deleteStatement, username)
	if err != nil {
		p.psqlLogger.Errorf("[ERROR] could not delete data with error : %v\n", err)
		return err
	}
	if row.RowsAffected() != 1 {
		p.psqlLogger.Errorf("[ERROR] no row found to delete")
		return errors.New("no row found to delete")
	}
	p.psqlLogger.Printf("Successfuly deleted user : %v", username)
	return nil
}

// InsertAppData inserts app in PostgreSql table
func (p *PostgreSqlRepo) InsertAppData(appData *domain.ApplicationData) error {
	newApplicationData := domain.ApplicationData{}
	insertStatement := "INSERT INTO apps (name, description, is_running, created_timestamp, updated_timestamp) VALUES ($1, $2, $3, $4, $5) RETURNING name"

	row := p.conn.QueryRow(p.ctx, insertStatement, appData.Name, appData.Description, appData.IsRunning, appData.CreatedTimestamp, appData.UpdatedTimestamp)
	err := row.Scan(&newApplicationData.Name)
	if err != nil {
		p.psqlLogger.Errorf("[ERROR] could not insert app with error : %v\n", err)
		return err
	}
	p.psqlLogger.Printf("Successfuly inserted app: %+v", newApplicationData.Name)
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

	if len(filters) > 0 && len(filters[0]) >= 3 {
		selectStatement := "SELECT * FROM apps where ("
		for i, filterParams := range filters {
			if len(filterParams) == 3 {
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
						selectStatement += filterParams[0] + " NOT ILIKE @" + descriptionPostgresID
						filterArguments[descriptionPostgresID] = "%" + filterParams[2] + "%"
					} else {
						selectStatement += filterParams[0] + " ILIKE @" + descriptionPostgresID
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
				p.psqlLogger.Errorf("[ERROR] Invalid filter")
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
				selectStatement += ") AND name=@app_name"
				filterArguments["app_name"] = appname
				break
			}

		}
		p.psqlLogger.Println(selectStatement)
		rows, err = p.conn.Query(p.ctx, selectStatement, filterArguments)
		if err != nil {
			p.psqlLogger.Errorf("[ERROR] could not retrieve app with error : %v\n", err)
			return nil, err
		}

	} else {
		selectStatement = "SELECT * FROM apps where name=$1"
		p.psqlLogger.Println(selectStatement)
		rows, err = p.conn.Query(p.ctx, selectStatement, appname)
		if err != nil {
			p.psqlLogger.Errorf("[ERROR] could not retrieve app with error : %v\n", err)
			return nil, err
		}
	}

	for rows.Next() {
		applicationData := &domain.ApplicationData{}
		err := rows.Scan(&applicationData.Name, &applicationData.Description, &applicationData.IsRunning,
			&applicationData.CreatedTimestamp, &applicationData.UpdatedTimestamp)
		if err != nil {
			p.psqlLogger.Errorf("[ERROR] could not scan app with error : %v\n", err)
			return nil, err
		}
		applicationsData = append(applicationsData, applicationData)
	}

	p.psqlLogger.Printf("Successfuly retrieved apps: %+v", applicationsData)
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
		p.psqlLogger.Errorf("[ERROR] could not update app with error : %v\n", err)
		return err
	}
	if row.RowsAffected() != 1 {
		p.psqlLogger.Errorf("[ERROR] no row found to update")
		return errors.New("no row found to update")
	}
	p.psqlLogger.Printf("Successfuly updated app: %+v", appData.Name)
	return nil
}

// DeleteAppData deletes app from PostgreSql table
func (p *PostgreSqlRepo) DeleteAppData(appName, userName string) error {
	updateStatement := "UPDATE  users SET applications=array_remove(applications, $1) WHERE username=$2"

	row, err := p.conn.Exec(p.ctx, updateStatement, appName, userName)
	if err != nil {
		p.psqlLogger.Errorf("[ERROR] could not remove app : %v from user : %v with error : %v\n", appName, userName, err)
		return err
	}
	if row.RowsAffected() != 1 {
		p.psqlLogger.Errorf("[ERROR] no row found to update")
		return errors.New("no row found to update")
	}
	deleteStatement := "DELETE FROM apps WHERE name = $1"

	row, err = p.conn.Exec(p.ctx, deleteStatement, appName)
	if err != nil {
		p.psqlLogger.Errorf("[ERROR] could not delete app :  %v  with error : %v\n", appName, err)
		return err
	}
	if row.RowsAffected() != 1 {
		p.psqlLogger.Errorf("[ERROR] no row found to delete")
		return errors.New("no row found to delete")
	}

	p.psqlLogger.Printf("Successfuly deleted user app : %+v", appName)
	return nil
}
