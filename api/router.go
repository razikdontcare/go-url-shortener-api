package api

import (
	"context"
	"encoding/json"
	"net/http"
	"razikdontcare/url-shortener/internal/config"
	"razikdontcare/url-shortener/internal/database"
	"razikdontcare/url-shortener/internal/handlers"
	"razikdontcare/url-shortener/internal/helpers"
	"razikdontcare/url-shortener/internal/models"

	"github.com/gorilla/mux"
)

// NewRouter creates a new router with all routes configured
func NewRouter(db *database.MongoDB, cfg *config.Config) *mux.Router {
	r := mux.NewRouter()
	h := handlers.NewHandler(db, cfg)

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]string{"message": "URL Shortener API"}
		json.NewEncoder(w).Encode(response)
	}).Methods("GET")

	// Public endpoint for redirects
	r.HandleFunc("/{shortCode}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		shortCode := vars["shortCode"]
		h.RedirectHandler(w, r, shortCode)
	}).Methods("GET")

	// Password verification endpoint (public)
	r.HandleFunc("/{shortCode}/verify", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		shortCode := vars["shortCode"]
		h.VerifyPasswordHandler(w, r, shortCode)
	}).Methods("POST")

	// API endpoints (protected)
	apiRouter := r.PathPrefix("/api").Subrouter()
	apiRouter.Use(func(next http.Handler) http.Handler {
		return apiKeyMiddleware(next, db)
	})

	// URL shortener routes
	apiRouter.HandleFunc("/shorten", h.CreateShortURLHandler).Methods("POST")
	apiRouter.HandleFunc("/url/{shortCode}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		shortCode := vars["shortCode"]
		h.GetURLHandler(w, r, shortCode)
	}).Methods("GET")

	apiRouter.HandleFunc("/url/{shortCode}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		shortCode := vars["shortCode"]
		h.UpdateURLHandler(w, r, shortCode)
	}).Methods("PUT")

	apiRouter.HandleFunc("/url/{shortCode}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		shortCode := vars["shortCode"]
		h.DeleteURLHandler(w, r, shortCode)
	}).Methods("DELETE")

	apiRouter.HandleFunc("/urls", h.ListURLsHandler).Methods("GET")

	// API key management routes - only accessible by admin API keys
	adminRouter := apiRouter.PathPrefix("/keys").Subrouter()
	adminRouter.Use(func(next http.Handler) http.Handler {
		return adminAPIKeyMiddleware(next, db)
	})

	adminRouter.HandleFunc("", h.CreateAPIKeyHandler).Methods("POST")
	adminRouter.HandleFunc("", h.ListAPIKeysHandler).Methods("GET")
	adminRouter.HandleFunc("/{id}", h.GetAPIKeyHandler).Methods("GET")
	adminRouter.HandleFunc("/{id}", h.UpdateAPIKeyHandler).Methods("PUT")
	adminRouter.HandleFunc("/{id}", h.DeleteAPIKeyHandler).Methods("DELETE")

	return r
}

// Middleware to validate API key
func apiKeyMiddleware(next http.Handler, db *database.MongoDB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get(models.APIKeyHeader)

		if apiKey == "" {
			helpers.RespondWithError(w, http.StatusUnauthorized, "API key is required")
			return
		}

		// Validate API key against database
		if !db.IsValidAPIKey(apiKey) {
			helpers.RespondWithError(w, http.StatusUnauthorized, "Invalid API key")
			return
		}

		// Store API key in context
		ctx := r.Context()
		ctx = context.WithValue(ctx, models.APIKeyContextKey, apiKey)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Middleware to validate admin API key
func adminAPIKeyMiddleware(next http.Handler, db *database.MongoDB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get(models.APIKeyHeader)

		// This is a secondary check - the apiKeyMiddleware should have already verified
		// that an API key exists and is valid, but we check again just to be safe
		if apiKey == "" {
			helpers.RespondWithError(w, http.StatusUnauthorized, "API key is required")
			return
		}

		// Check if API key has admin privileges
		if !db.IsAdminAPIKey(apiKey) {
			helpers.RespondWithError(w, http.StatusForbidden, "This operation requires admin privileges")
			return
		}

		next.ServeHTTP(w, r)
	})
}
