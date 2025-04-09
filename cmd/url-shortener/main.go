package main

import (
	"fmt"
	"log"
	"net/http"

	"razikdontcare/url-shortener/api"
	"razikdontcare/url-shortener/internal/config"
	"razikdontcare/url-shortener/internal/database"
)

func main() {
	// Load configuration from environment variables
	cfg := config.LoadConfig()

	// Connect to MongoDB
	db, err := database.NewMongoDB(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("Error closing MongoDB connection: %v", err)
		}
	}()

	// Initialize router with MongoDB and config
	router := api.NewRouter(db, cfg)

	// Start server
	serverAddr := fmt.Sprintf(":%s", cfg.ServerPort)
	log.Printf("Starting server on %s", serverAddr)
	if err := http.ListenAndServe(serverAddr, router); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}
