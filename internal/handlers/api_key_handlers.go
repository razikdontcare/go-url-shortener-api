package handlers

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"razikdontcare/url-shortener/internal/helpers"
	"razikdontcare/url-shortener/internal/models"
	"time"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// CreateAPIKeyRequest is the structure for API key creation requests
type CreateAPIKeyRequest struct {
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"`
	IsAdmin     bool       `json:"isAdmin"`
}

// UpdateAPIKeyRequest is the structure for API key update requests
type UpdateAPIKeyRequest struct {
	Name        *string    `json:"name,omitempty"`
	Description *string    `json:"description,omitempty"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"`
	IsActive    *bool      `json:"isActive,omitempty"`
	IsAdmin     *bool      `json:"isAdmin,omitempty"`
}

// CreateAPIKeyHandler creates a new API key
func (h *Handler) CreateAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req CreateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helpers.RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// Validate request
	if req.Name == "" {
		helpers.RespondWithError(w, http.StatusBadRequest, "Name is required")
		return
	}

	// Generate a new API key
	key, err := generateSecureToken(32) // 32 bytes = 256 bits
	if err != nil {
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to generate API key")
		return
	}

	// Create new API key
	apiKey := &models.APIKey{
		ID:          primitive.NewObjectID(),
		Key:         key,
		Name:        req.Name,
		Description: req.Description,
		CreatedAt:   time.Now(),
		ExpiresAt:   req.ExpiresAt,
		IsActive:    true,
		IsAdmin:     req.IsAdmin, // Set admin status from request
	}

	// Save to database
	if err := h.db.SaveAPIKey(apiKey); err != nil {
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to save API key")
		return
	}

	// Return success response
	helpers.RespondWithJSON(w, http.StatusCreated, models.APIResponse{
		Data: apiKey,
	})
}

// ListAPIKeysHandler retrieves all API keys
func (h *Handler) ListAPIKeysHandler(w http.ResponseWriter, r *http.Request) {
	apiKeys, err := h.db.ListAPIKeys()
	if err != nil {
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to retrieve API keys")
		return
	}

	// Return success response
	helpers.RespondWithJSON(w, http.StatusOK, models.APIResponse{
		Data: apiKeys,
	})
}

// GetAPIKeyHandler retrieves an API key by ID
func (h *Handler) GetAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	// Validate ID
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		helpers.RespondWithError(w, http.StatusBadRequest, "Invalid API key ID")
		return
	}

	// Get API key from database
	apiKey, err := h.db.GetAPIKeyByID(objectID)
	if err != nil {
		helpers.RespondWithError(w, http.StatusNotFound, "API key not found")
		return
	}

	// Return success response
	helpers.RespondWithJSON(w, http.StatusOK, models.APIResponse{
		Data: apiKey,
	})
}

// UpdateAPIKeyHandler updates an API key
func (h *Handler) UpdateAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	// Validate ID
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		helpers.RespondWithError(w, http.StatusBadRequest, "Invalid API key ID")
		return
	}

	// Get existing API key
	apiKey, err := h.db.GetAPIKeyByID(objectID)
	if err != nil {
		helpers.RespondWithError(w, http.StatusNotFound, "API key not found")
		return
	}

	// Parse request
	var req UpdateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helpers.RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// Update fields if provided
	if req.Name != nil {
		apiKey.Name = *req.Name
	}

	if req.Description != nil {
		apiKey.Description = *req.Description
	}

	if req.ExpiresAt != nil {
		apiKey.ExpiresAt = req.ExpiresAt
	}

	if req.IsActive != nil {
		apiKey.IsActive = *req.IsActive
	}

	if req.IsAdmin != nil {
		apiKey.IsAdmin = *req.IsAdmin
	}

	// Update in database
	if err := h.db.UpdateAPIKey(apiKey); err != nil {
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to update API key")
		return
	}

	// Return success response
	helpers.RespondWithJSON(w, http.StatusOK, models.APIResponse{
		Data: apiKey,
	})
}

// DeleteAPIKeyHandler deletes an API key
func (h *Handler) DeleteAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	// Validate ID
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		helpers.RespondWithError(w, http.StatusBadRequest, "Invalid API key ID")
		return
	}

	// Check if API key exists
	_, err = h.db.GetAPIKeyByID(objectID)
	if err != nil {
		helpers.RespondWithError(w, http.StatusNotFound, "API key not found")
		return
	}

	// Delete API key
	if err := h.db.DeleteAPIKey(objectID); err != nil {
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to delete API key")
		return
	}

	// Return success response
	helpers.RespondWithJSON(w, http.StatusOK, models.APIResponse{
		Data: map[string]string{"message": "API key deleted successfully"},
	})
}

// Helper function to generate a secure random token
func generateSecureToken(length int) (string, error) {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	for i, b := range bytes {
		bytes[i] = chars[b%byte(len(chars))]
	}
	return string(bytes), nil
}
