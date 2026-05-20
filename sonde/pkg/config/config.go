/*
Package config contient toutes les configurations et les moyens
de les importer dans le code
*/
package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	ServerAddress string
	ServerPort    string
	DatabaseURI   string
	Secret        string
}

func LoadConfig() *Config {
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found, using environment variables")
	}

	config := Config{
		ServerAddress: getEnv("SERVER_ADDRESS", "0.0.0.0"),
		ServerPort:    getEnv("SERVER_PORT", "8888"),
		Secret:        getEnv("SECRET", ""),
	}
	return &config
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
