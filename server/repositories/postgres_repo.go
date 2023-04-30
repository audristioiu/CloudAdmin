package repositories

import (
	"cloudadmin/domain"
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/jackc/pgx/v5"
)

// PostgresSqlRepo represents info about PostgreSql
type PostgreSqlRepo struct {
	ctx  context.Context
	conn *pgx.Conn
}

// NewPostgreSqlRepo returns a new PostgreSql repo
func NewPostgreSqlRepo(ctx context.Context, username, password, host, databaseName string, port int) *PostgreSqlRepo {
	url := fmt.Sprintf("postgres://%s:%s@%s:%d/%s", username, password, host, port, databaseName)

	dbPool, err := pgx.Connect(ctx, url)
	if err != nil {
		log.Printf("[ERROR] could not connect to database : %v\n", err)
		return nil
	}

	return &PostgreSqlRepo{
		ctx:  context.Background(),
		conn: dbPool,
	}
}

// InsertUserData inserts user in PostgreSql table
func (p *PostgreSqlRepo) InsertUserData(userData *domain.UserData) error {
	newUserData := domain.UserData{}
	insertStatement := "INSERT INTO users (username, password, city_address,want_notify,applications,user_id, role) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING username"

	row := p.conn.QueryRow(p.ctx, insertStatement, userData.UserName, userData.Password, userData.CityAddress, userData.WantNotify,
		userData.Applications, userData.UserID, userData.Role)
	err := row.Scan(&newUserData.UserName)
	if err != nil {
		log.Printf("[ERROR] could not insert data with error : %v\n", err)
		return err
	}
	log.Printf("Successfuly inserted : %+v", newUserData)
	return nil
}

// GetUserData retrieves user from PostgreSql table
func (p *PostgreSqlRepo) GetUserData(username string) (*domain.UserData, error) {
	userData := domain.UserData{}
	selectStatement := "SELECT * FROM users where username=$1"

	row := p.conn.QueryRow(p.ctx, selectStatement, username)
	err := row.Scan(&userData.UserName, &userData.Password, &userData.CityAddress, &userData.WantNotify, &userData.Applications, &userData.UserID, &userData.Role)
	if err != nil {
		log.Printf("[ERROR] could not retrieve data with error : %v\n", err)
		return nil, err
	}
	log.Printf("Successfuly retrieved : %+v", userData)
	return &userData, nil
}

func (p *PostgreSqlRepo) GetUserDataWithUUID(userID string) (*domain.UserData, error) {
	userData := domain.UserData{}
	selectStatement := "SELECT * FROM users where user_id=$1"

	row := p.conn.QueryRow(p.ctx, selectStatement, userID)
	err := row.Scan(&userData.UserName, &userData.Password, &userData.CityAddress, &userData.WantNotify, &userData.Applications, &userData.UserID, &userData.Role)
	if err != nil {
		log.Printf("[ERROR] could not retrieve data with error : %v\n", err)
		return nil, err
	}
	log.Printf("Successfuly retrieved : %+v", userData)
	return &userData, nil
}

// UpdateUserData updates user from PostgreSql table
func (p *PostgreSqlRepo) UpdateUserData(userData *domain.UserData) error {
	updateStatement := "UPDATE  users SET city_address=$1, want_notify=$2, password=$3 WHERE username=$4"

	row, err := p.conn.Exec(p.ctx, updateStatement, userData.CityAddress, userData.WantNotify, userData.Password, userData.UserName)
	if err != nil {
		log.Printf("[ERROR] could not update data with error : %v\n", err)
		return err
	}
	if row.RowsAffected() != 1 {
		log.Printf("[ERROR] no row found to update")
		return errors.New("no row found to update")
	}
	log.Printf("Successfuly updated with : %+v", userData)
	return nil
}

// UpdateUserRoleData updates user role from PostgreSql table
func (p *PostgreSqlRepo) UpdateUserRoleData(role, userID string, userData *domain.UserData) error {
	updateStatement := "UPDATE  users SET role=$1, user_id=$2 WHERE username=$3"

	row, err := p.conn.Exec(p.ctx, updateStatement, role, userID, userData.UserName)
	if err != nil {
		log.Printf("[ERROR] could not update data with error : %v\n", err)
		return err
	}
	if row.RowsAffected() != 1 {
		log.Printf("[ERROR] no row found to update")
		return errors.New("no row found to update")
	}
	log.Printf("Successfuly updated with : %v", role)
	return nil
}

// UpdateUserAppsData updates user apps from PostgreSql table
func (p *PostgreSqlRepo) UpdateUserAppsData(appName, userName string) error {
	updateStatement := "UPDATE  users SET applications=array_append(applications, $1) WHERE username=$2"

	row, err := p.conn.Exec(p.ctx, updateStatement, appName, userName)
	if err != nil {
		log.Printf("[ERROR] could not update user: %v with the new app : %v  with error : %v\n", userName, appName, err)
		return err
	}
	if row.RowsAffected() != 1 {
		log.Printf("[ERROR] no row found to update")
		return errors.New("no row found to update")
	}
	log.Printf("Successfuly updated user apps with : %+v", appName)
	return nil
}

// DeleteUserData deletes user from PostgreSql table
func (p *PostgreSqlRepo) DeleteUserData(username string) error {
	deleteStatement := "DELETE FROM users WHERE username=$1"

	row, err := p.conn.Exec(p.ctx, deleteStatement, username)
	if err != nil {
		log.Printf("[ERROR] could not delete data with error : %v\n", err)
		return err
	}
	if row.RowsAffected() != 1 {
		log.Printf("[ERROR] no row found to delete")
		return errors.New("no row found to delete")
	}
	log.Printf("Successfuly deleted user : %v", username)
	return nil
}

// InsertAppData inserts app in PostgreSql table
func (p *PostgreSqlRepo) InsertAppData(appData *domain.ApplicationData) error {
	newApplicationData := domain.ApplicationData{}
	insertStatement := "INSERT INTO apps (name, description, is_running) VALUES ($1, $2, $3) RETURNING name"

	row := p.conn.QueryRow(p.ctx, insertStatement, appData.Name, appData.Description, appData.IsRunning)
	err := row.Scan(&newApplicationData.Name)
	if err != nil {
		log.Printf("[ERROR] could not insert data with error : %v\n", err)
		return err
	}
	log.Printf("Successfuly inserted : %+v", newApplicationData)
	return nil
}

// GetAppData retrieves app from PostgreSql table
func (p *PostgreSqlRepo) GetAppData(appname string) (*domain.ApplicationData, error) {
	applicationData := domain.ApplicationData{}
	selectStatement := "SELECT * FROM apps where name=$1"

	row := p.conn.QueryRow(p.ctx, selectStatement, appname)
	err := row.Scan(&applicationData.Name, &applicationData.Description, &applicationData.IsRunning)
	if err != nil {
		log.Printf("[ERROR] could not retrieve data with error : %v\n", err)
		return nil, err
	}
	log.Printf("Successfuly retrieved : %+v", applicationData)
	return &applicationData, nil
}

// UpdateAppData updates app from PostgreSql table
func (p *PostgreSqlRepo) UpdateAppData(appData *domain.ApplicationData) error {
	updateStatement := "UPDATE  apps SET description=$1, is_running=$2 WHERE name=$3"

	row, err := p.conn.Exec(p.ctx, updateStatement, appData.Description, appData.IsRunning, appData.Name)
	if err != nil {
		log.Printf("[ERROR] could not update data with error : %v\n", err)
		return err
	}
	if row.RowsAffected() != 1 {
		log.Printf("[ERROR] no row found to update")
		return errors.New("no row found to update")
	}
	log.Printf("Successfuly updated with : %+v", appData)
	return nil
}

// DeleteAppData deletes app from PostgreSql table
func (p *PostgreSqlRepo) DeleteAppData(appName, userName string) error {
	updateStatement := "UPDATE  users SET applications=array_remove(applications, $1) WHERE username=$2"

	row, err := p.conn.Exec(p.ctx, updateStatement, appName, userName)
	if err != nil {
		log.Printf("[ERROR] could not update user: %v with deleting app : %v  with error : %v\n", userName, appName, err)
		return err
	}
	if row.RowsAffected() != 1 {
		log.Printf("[ERROR] no row found to update")
		return errors.New("no row found to update")
	}
	deleteStatement := "DELETE FROM apps WHERE name = $1"

	row, err = p.conn.Exec(p.ctx, deleteStatement, appName)
	if err != nil {
		log.Printf("[ERROR] could not delete app :  %v  with error : %v\n", appName, err)
		return err
	}
	if row.RowsAffected() != 1 {
		log.Printf("[ERROR] no row found to delete")
		return errors.New("no row found to delete")
	}

	log.Printf("Successfuly deleted user app : %+v", appName)
	return nil
}
