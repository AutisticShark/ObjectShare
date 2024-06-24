package config

import "github.com/spf13/viper"

var (
	Viper  = viper.New()
	Config = &ServiceConfig{}
)

func init() {
	Viper.SetConfigName("config")
	Viper.SetConfigType("json")
	Viper.AddConfigPath("/etc/object-share/")
	Viper.AddConfigPath(".")

	err := Viper.ReadInConfig()
	if err != nil {
		panic(err)
	}

	err = Viper.Unmarshal(&Config)
	if err != nil {
		panic(err)
	}
}

func GetVersion() string {
	return "0.0.1"
}
