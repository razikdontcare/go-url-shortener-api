package helpers

import (
	"encoding/json"
	"net/http"
	"razikdontcare/url-shortener/internal/models"
	"strconv"
)

func RespondWithJSON(w http.ResponseWriter, statusCode int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(payload)
}

func RespondWithError(w http.ResponseWriter, statusCode int, message string) {
	RespondWithJSON(w, statusCode, models.APIResponse{
		Error: &models.APIError{
			Code:    statusCode,
			Message: message,
		},
	})
}

// ParseInt safely parses a string to int, returning a default value of 1 if parsing fails
func ParseInt(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 1, err
	}
	if n < 1 {
		return 1, nil // Ensure positive value
	}
	return n, nil
}
