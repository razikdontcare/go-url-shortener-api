package handlers

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"razikdontcare/url-shortener/internal/config"
	"razikdontcare/url-shortener/internal/database"
	"razikdontcare/url-shortener/internal/helpers"
	"razikdontcare/url-shortener/internal/models"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

// Handler represents the handler dependencies
type Handler struct {
	db  *database.MongoDB
	cfg *config.Config
}

// NewHandler creates a new handler instance
func NewHandler(db *database.MongoDB, cfg *config.Config) *Handler {
	return &Handler{
		db:  db,
		cfg: cfg,
	}
}

// CreateShortURLHandler handles short URL creation
func (h *Handler) CreateShortURLHandler(w http.ResponseWriter, r *http.Request) {
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
	existingURL, err := h.db.FindURLByShortCode(shortCode)
	if err == nil && existingURL != nil {
		helpers.RespondWithError(w, http.StatusConflict, "Custom short code already in use")
		return
	}

	// Get base URL from config or request host
	baseURL := h.cfg.BaseURL
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
	if err := h.db.SaveURL(&shortURL); err != nil {
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to save URL")
		return
	}

	// Return success response
	helpers.RespondWithJSON(w, http.StatusCreated, models.APIResponse{
		Data: shortURL,
	})
}

// GetURLHandler retrieves short URL details
func (h *Handler) GetURLHandler(w http.ResponseWriter, r *http.Request, shortCode string) {
	shortURL, err := h.db.FindURLByShortCode(shortCode)
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

	helpers.RespondWithJSON(w, http.StatusOK, models.APIResponse{
		Data: shortURL,
	})
}

// RedirectHandler handles redirection from short URL to original URL
func (h *Handler) RedirectHandler(w http.ResponseWriter, r *http.Request, shortCode string) {
	shortURL, err := h.db.FindURLByShortCode(shortCode)
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

	go func() {
		// Run this in a goroutine so it doesn't block the redirect
		if err := h.db.IncrementClicks(shortURL.ID.Hex(), referrer, browser, platform); err != nil {
			// Just log the error, don't affect user experience
			fmt.Printf("Failed to update analytics: %v\n", err)
		}
	}()

	http.Redirect(w, r, shortURL.OriginalURL, http.StatusMovedPermanently)
}

// VerifyPasswordHandler verifies the password for password-protected URLs
func (h *Handler) VerifyPasswordHandler(w http.ResponseWriter, r *http.Request, shortCode string) {
	// Get URL from database
	shortURL, err := h.db.FindURLByShortCode(shortCode)
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

// UpdateURLHandler updates an existing short URL
func (h *Handler) UpdateURLHandler(w http.ResponseWriter, r *http.Request, shortCode string) {
	// Retrieve existing short URL
	shortURL, err := h.db.FindURLByShortCode(shortCode)
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
	if err := h.db.UpdateURL(shortURL); err != nil {
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to update URL")
		return
	}

	// Return updated URL
	helpers.RespondWithJSON(w, http.StatusOK, models.APIResponse{
		Data: shortURL,
	})
}

// DeleteURLHandler deletes a short URL
func (h *Handler) DeleteURLHandler(w http.ResponseWriter, r *http.Request, shortCode string) {
	// Check if short URL exists
	_, err := h.db.FindURLByShortCode(shortCode)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			helpers.RespondWithError(w, http.StatusNotFound, "Short URL not found")
		} else {
			helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to retrieve URL")
		}
		return
	}

	// Delete URL from database
	if err := h.db.DeleteURL(shortCode); err != nil {
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to delete URL")
		return
	}

	// Return success response
	helpers.RespondWithJSON(w, http.StatusOK, models.APIResponse{
		Data: map[string]string{"message": "Short URL deleted successfully"},
	})
}

// ListURLsHandler retrieves a paginated list of short URLs
func (h *Handler) ListURLsHandler(w http.ResponseWriter, r *http.Request) {
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
	urls, totalCount, err := h.db.ListURLs(page, limit)
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

// Helper function to generate a random short code
func generateShortCode(length int) (string, error) {
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

// Helper functions to parse user agent
func parseBrowser(userAgent string) string {
	userAgent = strings.ToLower(userAgent)

	switch {
	case strings.Contains(userAgent, "firefox"):
		return "Firefox"
	case strings.Contains(userAgent, "chrome") && !strings.Contains(userAgent, "edg"):
		return "Chrome"
	case strings.Contains(userAgent, "safari") && !strings.Contains(userAgent, "chrome"):
		return "Safari"
	case strings.Contains(userAgent, "edg"):
		return "Edge"
	case strings.Contains(userAgent, "opera"):
		return "Opera"
	default:
		return "Other"
	}
}

func parsePlatform(userAgent string) string {
	userAgent = strings.ToLower(userAgent)

	switch {
	case strings.Contains(userAgent, "windows"):
		return "Windows"
	case strings.Contains(userAgent, "mac os"):
		return "macOS"
	case strings.Contains(userAgent, "linux"):
		return "Linux"
	case strings.Contains(userAgent, "android"):
		return "Android"
	case strings.Contains(userAgent, "iphone") || strings.Contains(userAgent, "ipad"):
		return "iOS"
	default:
		return "Other"
	}
}
