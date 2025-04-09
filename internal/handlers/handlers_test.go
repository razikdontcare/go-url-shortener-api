package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"razikdontcare/url-shortener/internal/config"
	"razikdontcare/url-shortener/internal/helpers"
	"razikdontcare/url-shortener/internal/models"
	"strings"
	"testing"
	"time"

	"math/rand"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

// Define a Database interface that both our real MongoDB and our mock can implement
type Database interface {
	SaveURL(shortURL *models.ShortURL) error
	FindURLByShortCode(shortCode string) (*models.ShortURL, error)
	UpdateURL(shortURL *models.ShortURL) error
	DeleteURL(shortCode string) error
	ListURLs(page, limit int) ([]models.ShortURL, int64, error)
	IncrementClicks(shortCodeID string, referrer, browser, platform string) error
	Close() error
	SaveAPIKey(apiKey *models.APIKey) error
	GetAPIKey(key string) (*models.APIKey, error)
	GetAPIKeyByID(id primitive.ObjectID) (*models.APIKey, error)
	ListAPIKeys() ([]models.APIKey, error)
	UpdateAPIKey(apiKey *models.APIKey) error
	DeleteAPIKey(id primitive.ObjectID) error
	IsValidAPIKey(key string) bool
	IsAdminAPIKey(key string) bool
}

// MockDB represents a mock database implementation for testing
type MockDB struct {
	mock.Mock
}

// Implement all the Database interface methods
func (m *MockDB) SaveURL(shortURL *models.ShortURL) error {
	args := m.Called(shortURL)
	return args.Error(0)
}

func (m *MockDB) FindURLByShortCode(shortCode string) (*models.ShortURL, error) {
	args := m.Called(shortCode)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ShortURL), args.Error(1)
}

func (m *MockDB) UpdateURL(shortURL *models.ShortURL) error {
	args := m.Called(shortURL)
	return args.Error(0)
}

func (m *MockDB) DeleteURL(shortCode string) error {
	args := m.Called(shortCode)
	return args.Error(0)
}

func (m *MockDB) ListURLs(page, limit int) ([]models.ShortURL, int64, error) {
	args := m.Called(page, limit)
	return args.Get(0).([]models.ShortURL), args.Get(1).(int64), args.Error(2)
}

func (m *MockDB) IncrementClicks(shortCodeID string, referrer, browser, platform string) error {
	args := m.Called(shortCodeID, referrer, browser, platform)
	return args.Error(0)
}

func (m *MockDB) Close() error {
	args := m.Called()
	return args.Error(0)
}

// Handler wrapper for testing that uses our interface
type TestHandler struct {
	*Handler
	mockDB *MockDB
}

// Test setup helper - modified to use our interface
func setupHandlerTest(t *testing.T) (*TestHandler, *MockDB) {
	mockDB := new(MockDB)
	cfg := &config.Config{
		BaseURL: "http://localhost:8080",
	}

	// Create a modified Handler that uses our DB interface
	handler := &Handler{
		db:  nil, // We'll bypass this in the test handler
		cfg: cfg,
	}

	testHandler := &TestHandler{
		Handler: handler,
		mockDB:  mockDB,
	}

	return testHandler, mockDB
}

// Override methods to use our mock instead of the real DB
func (th *TestHandler) CreateShortURLHandler(w http.ResponseWriter, r *http.Request) {
	var req models.CreateShortURLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helpers.RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// Validate original URL
	if req.OriginalURL == "" {
		helpers.RespondWithError(w, http.StatusBadRequest, "Original URL is required")
		return
	}

	// Generate or use custom short code
	shortCode := req.CustomShortCode
	if shortCode == "" {
		var err error
		shortCode, err = generateShortCode(6)
		if err != nil {
			helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to generate short code")
			return
		}
	}

	// Check if custom code already exists
	existingURL, err := th.mockDB.FindURLByShortCode(shortCode)
	if err == nil && existingURL != nil {
		helpers.RespondWithError(w, http.StatusConflict, "Custom short code already in use")
		return
	}

	// Get base URL from config or request host
	baseURL := th.cfg.BaseURL
	if baseURL == "" {
		baseURL = "http://" + r.Host
	}

	// Create short URL object
	shortURL := models.ShortURL{
		ID:                primitive.NewObjectID(),
		ShortCode:         shortCode,
		OriginalURL:       req.OriginalURL,
		ShortURL:          fmt.Sprintf("%s/%s", baseURL, shortCode),
		CreatedAt:         time.Now(),
		ExpirationDate:    req.ExpirationDate,
		PasswordProtected: req.Password != "",
		AnalyticsID:       primitive.NewObjectID().Hex(),
	}

	// Hash the password if provided
	if req.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to hash password")
			return
		}
		shortURL.PasswordHash = string(hashedPassword)
	}

	// Store URL in database
	if err := th.mockDB.SaveURL(&shortURL); err != nil {
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to save URL")
		return
	}

	// Return success response
	helpers.RespondWithJSON(w, http.StatusCreated, models.APIResponse{
		Data: shortURL,
	})
}

// RedirectHandler overrides the original to use our mock DB
func (th *TestHandler) RedirectHandler(w http.ResponseWriter, r *http.Request, shortCode string) {
	shortURL, err := th.mockDB.FindURLByShortCode(shortCode)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			helpers.RespondWithError(w, http.StatusNotFound, "Short URL not found")
		} else {
			helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to retrieve URL")
		}
		return
	}

	// Check if URL has expired
	if shortURL.ExpirationDate != nil && time.Now().After(*shortURL.ExpirationDate) {
		helpers.RespondWithError(w, http.StatusGone, "Short URL has expired")
		return
	}

	// Check if URL is password protected
	if shortURL.PasswordProtected {
		// Check if there's a cookie with verified status for this shortcode
		cookie, err := r.Cookie("verified_" + shortCode)
		if err == nil && cookie.Value == "true" {
			// Already verified, proceed with redirection
		} else {
			// URL needs password, respond with a status code indicating password is required
			helpers.RespondWithJSON(w, http.StatusForbidden, models.APIResponse{
				Error: &models.APIError{
					Code:    http.StatusForbidden,
					Message: "Password protected URL",
					Details: "This URL requires a password for access",
				},
			})
			return
		}
	}

	// Update analytics
	referrer := r.Header.Get("Referer")
	userAgent := r.Header.Get("User-Agent")
	browser := parseBrowser(userAgent)
	platform := parsePlatform(userAgent)

	// In tests, we don't use goroutine to allow proper mocking
	if err := th.mockDB.IncrementClicks(shortURL.ID.Hex(), referrer, browser, platform); err != nil {
		// Just log the error, don't affect user experience
		fmt.Printf("Failed to update analytics: %v\n", err)
	}

	http.Redirect(w, r, shortURL.OriginalURL, http.StatusMovedPermanently)
}

// VerifyPasswordHandler overrides the original to use our mock DB
func (th *TestHandler) VerifyPasswordHandler(w http.ResponseWriter, r *http.Request, shortCode string) {
	// Get URL from database
	shortURL, err := th.mockDB.FindURLByShortCode(shortCode)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			helpers.RespondWithError(w, http.StatusNotFound, "Short URL not found")
		} else {
			helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to retrieve URL")
		}
		return
	}

	// Check if URL is actually password protected
	if !shortURL.PasswordProtected {
		helpers.RespondWithError(w, http.StatusBadRequest, "URL is not password protected")
		return
	}

	// Parse request body for password
	var req models.VerifyPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helpers.RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword([]byte(shortURL.PasswordHash), []byte(req.Password))
	if err != nil {
		helpers.RespondWithError(w, http.StatusUnauthorized, "Invalid password")
		return
	}

	// Set a cookie to remember verification status
	http.SetCookie(w, &http.Cookie{
		Name:     "verified_" + shortCode,
		Value:    "true",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		MaxAge:   3600, // 1 hour validity
		SameSite: http.SameSiteStrictMode,
	})

	// Return success
	helpers.RespondWithJSON(w, http.StatusOK, models.APIResponse{
		Data: map[string]string{
			"message": "Password verified successfully",
			"url":     shortURL.OriginalURL,
		},
	})
}

// UpdateURLHandler overrides the original to use our mock DB
func (th *TestHandler) UpdateURLHandler(w http.ResponseWriter, r *http.Request, shortCode string) {
	// Retrieve existing short URL
	shortURL, err := th.mockDB.FindURLByShortCode(shortCode)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			helpers.RespondWithError(w, http.StatusNotFound, "Short URL not found")
		} else {
			helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to retrieve URL")
		}
		return
	}

	// Parse request body
	var req models.UpdateShortURLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helpers.RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// Update fields if provided
	if req.NewOriginalURL != nil {
		shortURL.OriginalURL = *req.NewOriginalURL
	}

	if req.NewExpirationDate != nil {
		shortURL.ExpirationDate = req.NewExpirationDate
	}

	if req.NewPassword != nil {
		shortURL.PasswordProtected = *req.NewPassword != ""
		// Update password hash if a new password is provided
		if *req.NewPassword != "" {
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*req.NewPassword), bcrypt.DefaultCost)
			if err != nil {
				helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to hash password")
				return
			}
			shortURL.PasswordHash = string(hashedPassword)
		} else {
			// Clear password hash if password protection is removed
			shortURL.PasswordHash = ""
		}
	}

	// Update in database
	if err := th.mockDB.UpdateURL(shortURL); err != nil {
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to update URL")
		return
	}

	// Return updated URL
	helpers.RespondWithJSON(w, http.StatusOK, models.APIResponse{
		Data: shortURL,
	})
}

// DeleteURLHandler overrides the original to use our mock DB
func (th *TestHandler) DeleteURLHandler(w http.ResponseWriter, r *http.Request, shortCode string) {
	// Check if short URL exists
	_, err := th.mockDB.FindURLByShortCode(shortCode)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			helpers.RespondWithError(w, http.StatusNotFound, "Short URL not found")
		} else {
			helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to retrieve URL")
		}
		return
	}

	// Delete URL from database
	if err := th.mockDB.DeleteURL(shortCode); err != nil {
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to delete URL")
		return
	}

	// Return success response
	helpers.RespondWithJSON(w, http.StatusOK, models.APIResponse{
		Data: map[string]string{"message": "Short URL deleted successfully"},
	})
}

// ListURLsHandler overrides the original to use our mock DB
func (th *TestHandler) ListURLsHandler(w http.ResponseWriter, r *http.Request) {
	// Get pagination parameters
	query := r.URL.Query()
	page := 1
	limit := 10

	if pageStr := query.Get("page"); pageStr != "" {
		if p, err := helpers.ParseInt(pageStr); err == nil {
			page = p
		}
	}

	if limitStr := query.Get("limit"); limitStr != "" {
		if l, err := helpers.ParseInt(limitStr); err == nil {
			limit = l
		}
	}

	// Get URLs from database
	urls, totalCount, err := th.mockDB.ListURLs(page, limit)
	if err != nil {
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to retrieve URLs")
		return
	}

	// Return paginated results
	helpers.RespondWithJSON(w, http.StatusOK, models.APIResponse{
		Data: map[string]interface{}{
			"urls":       urls,
			"totalCount": totalCount,
			"page":       page,
			"limit":      limit,
		},
	})
}

// API key related handler methods for our TestHandler

// CreateAPIKeyHandler overrides the original to use our mock DB
func (th *TestHandler) CreateAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	var apiKey models.APIKey
	if err := json.NewDecoder(r.Body).Decode(&apiKey); err != nil {
		helpers.RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// Generate random API key
	randomKey, err := generateRandomString(32)
	if err != nil {
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to generate API key")
		return
	}

	// Set key properties
	apiKey.ID = primitive.NewObjectID()
	apiKey.Key = randomKey
	apiKey.CreatedAt = time.Now()

	// If not specified, set active by default
	if !apiKey.IsActive {
		apiKey.IsActive = true
	}

	// Store in database
	if err := th.mockDB.SaveAPIKey(&apiKey); err != nil {
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to create API key")
		return
	}

	// Return the created key
	helpers.RespondWithJSON(w, http.StatusCreated, models.APIResponse{
		Data: apiKey,
	})
}

// ListAPIKeysHandler overrides the original to use our mock DB
func (th *TestHandler) ListAPIKeysHandler(w http.ResponseWriter, r *http.Request) {
	apiKeys, err := th.mockDB.ListAPIKeys()
	if err != nil {
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to retrieve API keys")
		return
	}

	helpers.RespondWithJSON(w, http.StatusOK, models.APIResponse{
		Data: apiKeys,
	})
}

// DeleteAPIKeyHandler overrides the original to use our mock DB
func (th *TestHandler) DeleteAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	// Extract ID from URL
	vars := r.URL.Path
	parts := strings.Split(vars, "/")
	if len(parts) < 3 {
		helpers.RespondWithError(w, http.StatusBadRequest, "Invalid request")
		return
	}
	idStr := parts[len(parts)-1]

	// Convert string ID to ObjectID
	id, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		helpers.RespondWithError(w, http.StatusBadRequest, "Invalid API key ID")
		return
	}

	// Check if API key exists
	_, err = th.mockDB.GetAPIKeyByID(id)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			helpers.RespondWithError(w, http.StatusNotFound, "API key not found")
		} else {
			helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to retrieve API key")
		}
		return
	}

	// Delete API key
	if err := th.mockDB.DeleteAPIKey(id); err != nil {
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to delete API key")
		return
	}

	// Return success
	helpers.RespondWithJSON(w, http.StatusOK, models.APIResponse{
		Data: map[string]string{
			"message": "API key deleted successfully",
		},
	})
}

// Helper function to generate random string (simulating the one in api_key_handlers.go)
func generateRandomString(length int) (string, error) {
	// Simple implementation for testing purposes
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

// Test helper to create request and response recorder
func createRequestResponse(method, url string, body interface{}) (*http.Request, *httptest.ResponseRecorder) {
	var req *http.Request

	if body != nil {
		jsonBody, _ := json.Marshal(body)
		req, _ = http.NewRequest(method, url, bytes.NewBuffer(jsonBody))
	} else {
		req, _ = http.NewRequest(method, url, nil)
	}

	req.Header.Set("Content-Type", "application/json")
	return req, httptest.NewRecorder()
}

// Helper to parse APIResponse from response body
func parseResponse(t *testing.T, w *httptest.ResponseRecorder) models.APIResponse {
	var response models.APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	return response
}
