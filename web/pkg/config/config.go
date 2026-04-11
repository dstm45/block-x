/*
Package config contient toutes les configurations et les moyens
de les importer dans le code
*/
package config

import (
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/joho/godotenv"
)

type Config struct {
	ServerAddress string
	ServerPort    string
	DatabaseURI   string
	Secret        string
}

func LoadConfig() *Config {
	// Get the directory of the currently running file
	_, b, _, _ := runtime.Caller(0)
	basepath := filepath.Dir(b)

	// Construct the path to the .env file
	// Assumes the config file is in pkg/config, and .env is in the root
	envPath := filepath.Join(basepath, "..", "..", ".env")

	err := godotenv.Load(envPath)
	if err != nil {
		log.Println("No .env file found, using environment variables")
	}

	config := Config{
		ServerAddress: getEnv("SERVER_ADDRESS", "127.0.0.1"),
		ServerPort:    getEnv("SERVER_PORT", "8080"),
		DatabaseURI:   getEnv("DATABASE_URI", ""),
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
