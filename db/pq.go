package db

import (
	"ObjectShare/config"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"strconv"
)

func GetPostgresConnection() *gorm.DB {
	dsn := "host=" + config.Config.Db.Host + " port=" + strconv.Itoa(config.Config.Db.Port) +
		" user=" + config.Config.Db.User + " password=" + config.Config.Db.Password +
		" dbname=" + config.Config.Db.Database + " sslmode=disable TimeZone=Asia/Taipei"

	connection, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	err = connection.AutoMigrate(&FileList{})
	if err != nil {
		panic(err)
	}

	return connection
}
