package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Core Types

type ShortURL struct {
	ID                primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	ShortCode         string             `json:"shortCode" bson:"shortCode"`
	OriginalURL       string             `json:"originalUrl" bson:"originalUrl"`
	ShortURL          string             `json:"shortUrl" bson:"shortUrl"`
	CreatedAt         time.Time          `json:"createdAt" bson:"createdAt"`
	ExpirationDate    *time.Time         `json:"expirationDate,omitempty" bson:"expirationDate,omitempty"`
	PasswordProtected bool               `json:"passwordProtected" bson:"passwordProtected"`
	PasswordHash      string             `json:"-" bson:"passwordHash,omitempty"`
	AnalyticsID       string             `json:"analyticsId" bson:"analyticsId"`
}

type Analytics struct {
	ID           primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	ShortCodeID  string             `json:"shortCodeId" bson:"shortCodeId"`
	TotalClicks  int                `json:"totalClicks" bson:"totalClicks"`
	DailyClicks  []ClickDay         `json:"dailyClicks" bson:"dailyClicks"`
	Referers     []ReferrerCount    `json:"referrers" bson:"referrers"`
	Browsers     []BrowserCount     `json:"browsers" bson:"browsers"`
	Platforms    []PlatformCount    `json:"platforms" bson:"platforms"`
	LastAccessed *time.Time         `json:"lastAccessed,omitempty" bson:"lastAccessed,omitempty"`
}

type APIKey struct {
	ID          primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Key         string             `json:"key" bson:"key"`
	Name        string             `json:"name" bson:"name"`
	Description string             `json:"description,omitempty"`
	CreatedAt   time.Time          `json:"createdAt" bson:"createdAt"`
	ExpiresAt   *time.Time         `json:"expiresAt,omitempty" bson:"expiresAt,omitempty"`
	IsActive    bool               `json:"isActive" bson:"isActive"`
	IsAdmin     bool               `json:"isAdmin" bson:"isAdmin"`
}

// Helper Types

type ClickDay struct {
	Date   time.Time `json:"date" bson:"date"`
	Clicks int       `json:"clicks" bson:"clicks"`
}

type ReferrerCount struct {
	Referrer string `json:"referrer" bson:"referrer"`
	Count    int    `json:"count" bson:"count"`
}

type BrowserCount struct {
	Browser string `json:"browser" bson:"browser"`
	Count   int    `json:"count" bson:"count"`
}

type PlatformCount struct {
	Platform string `json:"platform" bson:"platform"`
	Count    int    `json:"count" bson:"count"`
}

// Request Types

type CreateShortURLRequest struct {
	OriginalURL     string     `json:"originalUrl"`
	CustomShortCode string     `json:"customShortCode,omitempty"`
	ExpirationDate  *time.Time `json:"expirationDate,omitempty"`
	Password        string     `json:"password,omitempty"`
}

type UpdateShortURLRequest struct {
	NewOriginalURL    *string    `json:"newOriginalUrl,omitempty"`
	NewExpirationDate *time.Time `json:"newExpirationDate,omitempty"`
	NewPassword       *string    `json:"newPassword,omitempty"`
}

type ListShortURLsRequest struct {
	Page  int `schema:"page"`
	Limit int `schema:"limit"`
}

// Adding a password verification request for password-protected URLs
type VerifyPasswordRequest struct {
	Password string `json:"password"`
}

// Response Types

type APIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

type APIResponse struct {
	Data  interface{} `json:"data,omitempty"`
	Error *APIError   `json:"error,omitempty"`
}

// Middleware Types

type contextKey string

const (
	APIKeyHeader     = "X-API-Key"
	APIKeyContextKey = contextKey("apiKey")
)
