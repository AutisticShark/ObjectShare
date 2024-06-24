package db

import (
	"ObjectShare/config"
	"gorm.io/gorm"
)

func GetConnection() *gorm.DB {
	switch config.Config.Db.Type {
	case "postgres":
		{
			return GetPostgresConnection()
		}
	default:
		panic("Unsupported database type")
		return nil
	}
}
