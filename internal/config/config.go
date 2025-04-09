package config

import (
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/joho/godotenv"
)

// Config holds application configuration
type Config struct {
	MongoURI                 string
	MongoDBName              string
	MongoTimeout             string
	APIKeys                  []string // This will be kept for fallback/bootstrap purposes
	ServerPort               string
	BaseURL                  string
	MongoURLsCollection      string
	MongoAnalyticsCollection string
	MongoAPIKeysCollection   string
}

// LoadConfig loads configuration from environment variables
func LoadConfig() *Config {
	// Find the project root to locate .env file
	_, b, _, _ := runtime.Caller(0)
	projectRoot := filepath.Join(filepath.Dir(b), "../..")

	// Load environment variables from .env file
	envFile := filepath.Join(projectRoot, ".env")
	if err := godotenv.Load(envFile); err != nil {
		log.Println("Warning: No .env file found or error loading it:", err)
	}

	// Get configuration from environment with defaults
	config := &Config{
		MongoURI:                 getEnv("MONGO_URI", "mongodb://localhost:27017"),
		MongoDBName:              getEnv("MONGO_DB_NAME", "url_shortener"),
		MongoTimeout:             getEnv("MONGO_TIMEOUT", "10s"),
		ServerPort:               getEnv("SERVER_PORT", "8080"),
		BaseURL:                  getEnv("BASE_URL", "http://localhost:8080"),
		MongoURLsCollection:      getEnv("MONGO_URLS_COLLECTION", "urls"),
		MongoAnalyticsCollection: getEnv("MONGO_ANALYTICS_COLLECTION", "analytics"),
		MongoAPIKeysCollection:   getEnv("MONGO_API_KEYS_COLLECTION", "apikeys"),
	}

	// Get API keys as comma-separated list (for fallback/bootstrap)
	apiKeysStr := getEnv("API_KEYS", "valid-api-key")
	if apiKeysStr != "" {
		config.APIKeys = []string{apiKeysStr} // In a real app, split by commas
	}

	return config
}

// Helper function to get environment variables with defaults
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}
