package db

import (
	"fmt"
	"net/url"
	"strings"
	"webauthndemo/pkg/model"

	"gorm.io/gorm/logger"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"

	gorm_logrus "github.com/onrik/gorm-logrus"

	"gorm.io/gorm"

	"os"
)

// New connects to the specified database by |href|
//   - mysql://user:password@host:3306/dbname?charset=utf8&parseTime=True&loc=Local
//   - postgresql://user:password@host:5439/dbname
//   - file://path-to-sqlite3-db-file
//
// Without creds specified in the DSN, it will look for the env vars DB_USER and DB_PASSWORD
func New(href string, debug bool) (*gorm.DB, error) {
	if href == "" {
		return nil, fmt.Errorf("empty DB DSN")
	}
	u, err := url.Parse(href)
	if err != nil {
		return nil, err
	}

	var defPort string
	switch u.Scheme {
	case "mysql":
		defPort = "3306"
	case "postgres", "postgresql":
		defPort = "5432"
	case "file":
		return openSqlite3(u.Path)
	default:
		return nil, fmt.Errorf("unknown database DSN scheme \"%s\"", href)
	}
	// get creds from DSN or fallback to environment
	var user, pass string
	if u.User != nil {
		user = u.User.Username()
		if p, ok := u.User.Password(); ok {
			pass = p
		}
	} else {
		user = os.Getenv("DB_USER")
		pass = os.Getenv("DB_PASSWORD")
	}

	dsn := strings.Builder{}
	if user != "" {
		dsn.WriteString(user)
		if pass != "" {
			dsn.WriteString(":")
			dsn.WriteString(pass)
		}
		dsn.WriteString("@")
	}
	dsn.WriteString("tcp(")
	dsn.WriteString(u.Hostname())
	dsn.WriteString(":")
	if u.Port() != "" {
		dsn.WriteString(u.Port())
	} else {
		dsn.WriteString(defPort)
	}
	dsn.WriteString(")/")

	dbname := u.Path[1:]
	db, err := gorm.Open(postgres.Open(dsn.String()), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	db.Exec(fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s;", dbname))

	dsn.WriteString(dbname)
	if u.Scheme == "mysql" {
		dsn.WriteString("?parseTime=True&loc=Local")
	}
	db, err = gorm.Open(postgres.Open(dsn.String()), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
		//Logger: gorm_logrus.New(),
	})
	if err != nil {
		return nil, err
	}
	return db, nil
}

func openSqlite3(path string) (*gorm.DB, error) {
	var l logger.Interface
	if s := os.Getenv("DB_LOG_SILENT"); s != "" {
		l = logger.Default.LogMode(logger.Silent)
	} else {
		l = gorm_logrus.New()
	}

	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{
		Logger: l,
	})
	if err != nil {
		return nil, err
	}

	return db, nil
}

// TestDB creates an sqlite test database if dbpath exists as a file. Get a shell to the db with:
//   - sqlite3 ./pkg/api/test_db.db
//
// If it starts with "mysql://", then it returns a connection to a live mysql test database.
func TestDB(dbpath string) *gorm.DB {
	var tdb *gorm.DB

	if dbpath[:8] != "mysql://" {
		db, err := openSqlite3(dbpath)
		if err != nil {
			return nil
		}
		tdb = db
	} else {
		testdb, err := New(dbpath, true)
		if err != nil {
			panic(err)
		}
		tdb = testdb
	}
	return tdb
}

// DropTestDB drop the test database
func DropTestDB(dbpath string) error {
	if dbpath[:8] != "mysql://" {
		if err := os.Remove(dbpath); err != nil {
			return err
		}
	} else {
		u, err := url.Parse(dbpath)
		if err != nil {
			return err
		}
		tdb, err := New(dbpath, true)
		if err != nil {
			return err
		}
		err = tdb.Exec(fmt.Sprintf("drop database %s", u.Path[1:])).Error
		return err
	}
	return nil
}

// AutoMigrate creates and alters the tables as needed between releases
func AutoMigrate(db *gorm.DB) error {
	err := db.AutoMigrate(
		&model.Customer{},
		&model.Contact{},
	)
	if err != nil {
		return err
	}

	return nil
}
