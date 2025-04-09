package handlers

import (
	"net/http"
	"razikdontcare/url-shortener/internal/models"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// Add API Key related methods to our mock
func (m *MockDB) SaveAPIKey(apiKey *models.APIKey) error {
	args := m.Called(apiKey)
	return args.Error(0)
}

func (m *MockDB) GetAPIKey(key string) (*models.APIKey, error) {
	args := m.Called(key)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.APIKey), args.Error(1)
}

func (m *MockDB) GetAPIKeyByID(id primitive.ObjectID) (*models.APIKey, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.APIKey), args.Error(1)
}

func (m *MockDB) ListAPIKeys() ([]models.APIKey, error) {
	args := m.Called()
	return args.Get(0).([]models.APIKey), args.Error(1)
}

func (m *MockDB) UpdateAPIKey(apiKey *models.APIKey) error {
	args := m.Called(apiKey)
	return args.Error(0)
}

func (m *MockDB) DeleteAPIKey(id primitive.ObjectID) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockDB) IsValidAPIKey(key string) bool {
	args := m.Called(key)
	return args.Bool(0)
}

func (m *MockDB) IsAdminAPIKey(key string) bool {
	args := m.Called(key)
	return args.Bool(0)
}

// TestCreateAPIKeyHandler tests the API key creation functionality
func TestCreateAPIKeyHandler(t *testing.T) {
	tests := []struct {
		name           string
		request        models.APIKey
		mockSetup      func(*MockDB)
		expectedStatus int
		checkResponse  func(*testing.T, models.APIResponse)
	}{
		{
			name: "Successfully Create API Key",
			request: models.APIKey{
				Name:        "Test API Key",
				Description: "API key for testing",
				IsActive:    true,
				IsAdmin:     false,
			},
			mockSetup: func(mockDB *MockDB) {
				mockDB.On("SaveAPIKey", mock.AnythingOfType("*models.APIKey")).Return(nil)
			},
			expectedStatus: http.StatusCreated,
			checkResponse: func(t *testing.T, resp models.APIResponse) {
				assert.Nil(t, resp.Error)
				assert.NotNil(t, resp.Data)
				data, ok := resp.Data.(map[string]interface{})
				assert.True(t, ok)
				assert.Equal(t, "Test API Key", data["name"])
				assert.Equal(t, "API key for testing", data["description"])
				assert.NotEmpty(t, data["key"])
				assert.Equal(t, true, data["isActive"])
				assert.Equal(t, false, data["isAdmin"])
			},
		},
		{
			name: "Database Error on Save",
			request: models.APIKey{
				Name:     "Test API Key",
				IsActive: true,
			},
			mockSetup: func(mockDB *MockDB) {
				mockDB.On("SaveAPIKey", mock.AnythingOfType("*models.APIKey")).Return(assert.AnError)
			},
			expectedStatus: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, resp models.APIResponse) {
				assert.NotNil(t, resp.Error)
				assert.Equal(t, http.StatusInternalServerError, resp.Error.Code)
				assert.Contains(t, resp.Error.Message, "Failed to create API key")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			handler, mockDB := setupHandlerTest(t)
			if tt.mockSetup != nil {
				tt.mockSetup(mockDB)
			}

			// Create request and response recorder
			req, rr := createRequestResponse(http.MethodPost, "/api/keys", tt.request)

			// Call handler
			handler.CreateAPIKeyHandler(rr, req)

			// Check status code
			assert.Equal(t, tt.expectedStatus, rr.Code)

			// Parse and check response
			response := parseResponse(t, rr)
			if tt.checkResponse != nil {
				tt.checkResponse(t, response)
			}

			// Verify all expectations were met
			mockDB.AssertExpectations(t)
		})
	}
}

// TestListAPIKeysHandler tests the listing of API keys
func TestListAPIKeysHandler(t *testing.T) {
	tests := []struct {
		name           string
		mockSetup      func(*MockDB)
		expectedStatus int
		checkResponse  func(*testing.T, models.APIResponse)
	}{
		{
			name: "Successfully List API Keys",
			mockSetup: func(mockDB *MockDB) {
				mockKeys := []models.APIKey{
					{
						ID:          primitive.NewObjectID(),
						Key:         "key1",
						Name:        "API Key 1",
						Description: "First test key",
						CreatedAt:   time.Now(),
						IsActive:    true,
						IsAdmin:     false,
					},
					{
						ID:          primitive.NewObjectID(),
						Key:         "key2",
						Name:        "API Key 2",
						Description: "Second test key",
						CreatedAt:   time.Now(),
						IsActive:    true,
						IsAdmin:     true,
					},
				}
				mockDB.On("ListAPIKeys").Return(mockKeys, nil)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp models.APIResponse) {
				assert.Nil(t, resp.Error)
				assert.NotNil(t, resp.Data)
				keys, ok := resp.Data.([]interface{})
				assert.True(t, ok)
				assert.Equal(t, 2, len(keys))
			},
		},
		{
			name: "Database Error",
			mockSetup: func(mockDB *MockDB) {
				mockDB.On("ListAPIKeys").Return([]models.APIKey{}, assert.AnError)
			},
			expectedStatus: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, resp models.APIResponse) {
				assert.NotNil(t, resp.Error)
				assert.Equal(t, http.StatusInternalServerError, resp.Error.Code)
				assert.Contains(t, resp.Error.Message, "Failed to retrieve API keys")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			handler, mockDB := setupHandlerTest(t)
			if tt.mockSetup != nil {
				tt.mockSetup(mockDB)
			}

			// Create request and response recorder
			req, rr := createRequestResponse(http.MethodGet, "/api/keys", nil)

			// Call handler
			handler.ListAPIKeysHandler(rr, req)

			// Check status code
			assert.Equal(t, tt.expectedStatus, rr.Code)

			// Parse and check response
			response := parseResponse(t, rr)
			if tt.checkResponse != nil {
				tt.checkResponse(t, response)
			}

			// Verify all expectations were met
			mockDB.AssertExpectations(t)
		})
	}
}

// TestDeleteAPIKeyHandler tests the deletion of API keys
func TestDeleteAPIKeyHandler(t *testing.T) {
	objectID := primitive.NewObjectID()
	idHex := objectID.Hex()

	tests := []struct {
		name           string
		keyID          string
		mockSetup      func(*MockDB)
		expectedStatus int
		checkResponse  func(*testing.T, models.APIResponse)
	}{
		{
			name:  "Successfully Delete API Key",
			keyID: idHex,
			mockSetup: func(mockDB *MockDB) {
				mockDB.On("GetAPIKeyByID", objectID).Return(&models.APIKey{
					ID:          objectID,
					Key:         "test-key",
					Name:        "Test Key",
					Description: "For testing",
					CreatedAt:   time.Now(),
					IsActive:    true,
				}, nil)
				mockDB.On("DeleteAPIKey", objectID).Return(nil)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp models.APIResponse) {
				assert.Nil(t, resp.Error)
				assert.NotNil(t, resp.Data)
				data, ok := resp.Data.(map[string]interface{})
				assert.True(t, ok)
				assert.Contains(t, data["message"], "API key deleted successfully")
			},
		},
		{
			name:  "Invalid Object ID",
			keyID: "invalid-id",
			mockSetup: func(mockDB *MockDB) {
				// No mock needed as it will fail before DB call
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, resp models.APIResponse) {
				assert.NotNil(t, resp.Error)
				assert.Equal(t, http.StatusBadRequest, resp.Error.Code)
				assert.Contains(t, resp.Error.Message, "Invalid API key ID")
			},
		},
		{
			name:  "API Key Not Found",
			keyID: idHex,
			mockSetup: func(mockDB *MockDB) {
				mockDB.On("GetAPIKeyByID", objectID).Return(nil, mongo.ErrNoDocuments)
			},
			expectedStatus: http.StatusNotFound,
			checkResponse: func(t *testing.T, resp models.APIResponse) {
				assert.NotNil(t, resp.Error)
				assert.Equal(t, http.StatusNotFound, resp.Error.Code)
				assert.Contains(t, resp.Error.Message, "API key not found")
			},
		},
		{
			name:  "Database Error on Delete",
			keyID: idHex,
			mockSetup: func(mockDB *MockDB) {
				mockDB.On("GetAPIKeyByID", objectID).Return(&models.APIKey{
					ID:          objectID,
					Key:         "test-key",
					Name:        "Test Key",
					Description: "For testing",
					CreatedAt:   time.Now(),
					IsActive:    true,
				}, nil)
				mockDB.On("DeleteAPIKey", objectID).Return(assert.AnError)
			},
			expectedStatus: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, resp models.APIResponse) {
				assert.NotNil(t, resp.Error)
				assert.Equal(t, http.StatusInternalServerError, resp.Error.Code)
				assert.Contains(t, resp.Error.Message, "Failed to delete API key")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			handler, mockDB := setupHandlerTest(t)
			if tt.mockSetup != nil {
				tt.mockSetup(mockDB)
			}

			// Create request and response recorder
			req, rr := createRequestResponse(http.MethodDelete, "/api/keys/"+tt.keyID, nil)

			// Fix: Use the API endpoint path to test the handler correctly
			// The DeleteAPIKeyHandler will extract the ID from the URL path
			handler.DeleteAPIKeyHandler(rr, req)

			// Check status code
			assert.Equal(t, tt.expectedStatus, rr.Code)

			// Parse and check response
			response := parseResponse(t, rr)
			if tt.checkResponse != nil {
				tt.checkResponse(t, response)
			}

			// Verify all expectations were met
			mockDB.AssertExpectations(t)
		})
	}
}
