package database

import (
	"context"
	"log"
	"razikdontcare/url-shortener/internal/config"
	"razikdontcare/url-shortener/internal/models"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

// MongoDB represents a MongoDB client
type MongoDB struct {
	client              *mongo.Client
	urlsCollection      *mongo.Collection
	analyticsCollection *mongo.Collection
	apiKeysCollection   *mongo.Collection
	cfg                 *config.Config
}

// NewMongoDB creates a new MongoDB client
func NewMongoDB(cfg *config.Config) (*MongoDB, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Connect to MongoDB
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(cfg.MongoURI))
	if err != nil {
		return nil, err
	}

	// Ping the database to verify connection
	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		return nil, err
	}

	// Initialize collections
	urlsCollection := client.Database(cfg.MongoDBName).Collection(cfg.MongoURLsCollection)
	analyticsCollection := client.Database(cfg.MongoDBName).Collection(cfg.MongoAnalyticsCollection)
	apiKeysCollection := client.Database(cfg.MongoDBName).Collection(cfg.MongoAPIKeysCollection)

	// Create indexes for URLs collection
	_, err = urlsCollection.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "shortCode", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return nil, err
	}

	// Create indexes for API Keys collection
	_, err = apiKeysCollection.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "key", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return nil, err
	}

	mongodb := &MongoDB{
		client:              client,
		urlsCollection:      urlsCollection,
		analyticsCollection: analyticsCollection,
		apiKeysCollection:   apiKeysCollection,
		cfg:                 cfg,
	}

	// Bootstrap API keys if collection is empty
	if err := mongodb.bootstrapAPIKeys(ctx); err != nil {
		log.Printf("Warning: Failed to bootstrap API keys: %v", err)
	}

	log.Println("Connected to MongoDB successfully")

	return mongodb, nil
}

// bootstrapAPIKeys ensures there is at least one API key in the database
func (m *MongoDB) bootstrapAPIKeys(ctx context.Context) error {
	// Check if there are any API keys
	count, err := m.apiKeysCollection.CountDocuments(ctx, bson.M{})
	if err != nil {
		return err
	}

	// If there are already API keys, don't bootstrap
	if count > 0 {
		return nil
	}

	// Use the API keys from the config as a fallback/bootstrap
	for _, key := range m.cfg.APIKeys {
		apiKey := models.APIKey{
			ID:        primitive.NewObjectID(),
			Key:       key,
			Name:      "Bootstrap Admin Key",
			CreatedAt: time.Now(),
			IsActive:  true,
			IsAdmin:   true, // Make bootstrap key an admin
		}

		_, err := m.apiKeysCollection.InsertOne(ctx, apiKey)
		if err != nil {
			return err
		}
		log.Printf("Bootstrapped admin API key: %s", key)
	}

	return nil
}

// Close closes the MongoDB connection
func (m *MongoDB) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return m.client.Disconnect(ctx)
}

// SaveURL saves a short URL to the database
func (m *MongoDB) SaveURL(shortURL *models.ShortURL) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if shortURL.ID.IsZero() {
		shortURL.ID = primitive.NewObjectID()
	}

	_, err := m.urlsCollection.InsertOne(ctx, shortURL)
	return err
}

// FindURLByShortCode finds a short URL by its short code
func (m *MongoDB) FindURLByShortCode(shortCode string) (*models.ShortURL, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var shortURL models.ShortURL
	filter := bson.M{"shortCode": shortCode}
	err := m.urlsCollection.FindOne(ctx, filter).Decode(&shortURL)
	if err != nil {
		return nil, err
	}

	return &shortURL, nil
}

// UpdateURL updates an existing short URL
func (m *MongoDB) UpdateURL(shortURL *models.ShortURL) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"shortCode": shortURL.ShortCode}
	update := bson.M{"$set": shortURL}
	_, err := m.urlsCollection.UpdateOne(ctx, filter, update)
	return err
}

// DeleteURL deletes a short URL by its short code
func (m *MongoDB) DeleteURL(shortCode string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"shortCode": shortCode}
	_, err := m.urlsCollection.DeleteOne(ctx, filter)
	return err
}

// ListURLs returns a paginated list of short URLs
func (m *MongoDB) ListURLs(page, limit int) ([]models.ShortURL, int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Calculate skip value for pagination
	skip := (page - 1) * limit

	// Find with pagination
	findOptions := options.Find().
		SetSkip(int64(skip)).
		SetLimit(int64(limit)).
		SetSort(bson.D{{Key: "createdAt", Value: -1}}) // Sort by creation date descending

	// Execute the query
	cursor, err := m.urlsCollection.Find(ctx, bson.M{}, findOptions)
	if err != nil {
		return nil, 0, err
	}
	defer cursor.Close(ctx)

	// Decode results
	var urls []models.ShortURL
	if err = cursor.All(ctx, &urls); err != nil {
		return nil, 0, err
	}

	// Count total documents
	count, err := m.urlsCollection.CountDocuments(ctx, bson.M{})
	if err != nil {
		return nil, 0, err
	}

	return urls, count, nil
}

// SaveAnalytics creates or updates an analytics record
func (m *MongoDB) SaveAnalytics(analytics *models.Analytics) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if analytics.ID.IsZero() {
		analytics.ID = primitive.NewObjectID()
	}

	filter := bson.M{"shortCodeId": analytics.ShortCodeID}
	update := bson.M{"$set": analytics}
	opts := options.Update().SetUpsert(true)
	_, err := m.analyticsCollection.UpdateOne(ctx, filter, update, opts)
	return err
}

// IncrementClicks increments the click count for a URL and updates analytics
func (m *MongoDB) IncrementClicks(shortCodeID string, referrer, browser, platform string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	// First, try to find an existing analytics record
	var analytics models.Analytics
	filter := bson.M{"shortCodeId": shortCodeID}
	err := m.analyticsCollection.FindOne(ctx, filter).Decode(&analytics)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			// Create a new analytics record if none exists
			analytics = models.Analytics{
				ID:          primitive.NewObjectID(),
				ShortCodeID: shortCodeID,
				TotalClicks: 1,
				DailyClicks: []models.ClickDay{{
					Date:   today,
					Clicks: 1,
				}},
				Referers:     []models.ReferrerCount{},
				Browsers:     []models.BrowserCount{},
				Platforms:    []models.PlatformCount{},
				LastAccessed: &now,
			}

			if referrer != "" {
				analytics.Referers = append(analytics.Referers, models.ReferrerCount{
					Referrer: referrer,
					Count:    1,
				})
			}

			if browser != "" {
				analytics.Browsers = append(analytics.Browsers, models.BrowserCount{
					Browser: browser,
					Count:   1,
				})
			}

			if platform != "" {
				analytics.Platforms = append(analytics.Platforms, models.PlatformCount{
					Platform: platform,
					Count:    1,
				})
			}

			return m.SaveAnalytics(&analytics)
		}
		return err
	}

	// Update existing analytics
	analytics.TotalClicks++
	analytics.LastAccessed = &now

	// Update daily clicks
	dayFound := false
	for i := range analytics.DailyClicks {
		if analytics.DailyClicks[i].Date.Year() == today.Year() &&
			analytics.DailyClicks[i].Date.Month() == today.Month() &&
			analytics.DailyClicks[i].Date.Day() == today.Day() {
			analytics.DailyClicks[i].Clicks++
			dayFound = true
			break
		}
	}

	if !dayFound {
		analytics.DailyClicks = append(analytics.DailyClicks, models.ClickDay{
			Date:   today,
			Clicks: 1,
		})
	}

	// Update referrer stats
	if referrer != "" {
		refFound := false
		for i := range analytics.Referers {
			if analytics.Referers[i].Referrer == referrer {
				analytics.Referers[i].Count++
				refFound = true
				break
			}
		}

		if !refFound {
			analytics.Referers = append(analytics.Referers, models.ReferrerCount{
				Referrer: referrer,
				Count:    1,
			})
		}
	}

	// Update browser stats
	if browser != "" {
		browserFound := false
		for i := range analytics.Browsers {
			if analytics.Browsers[i].Browser == browser {
				analytics.Browsers[i].Count++
				browserFound = true
				break
			}
		}

		if !browserFound {
			analytics.Browsers = append(analytics.Browsers, models.BrowserCount{
				Browser: browser,
				Count:   1,
			})
		}
	}

	// Update platform stats
	if platform != "" {
		platformFound := false
		for i := range analytics.Platforms {
			if analytics.Platforms[i].Platform == platform {
				analytics.Platforms[i].Count++
				platformFound = true
				break
			}
		}

		if !platformFound {
			analytics.Platforms = append(analytics.Platforms, models.PlatformCount{
				Platform: platform,
				Count:    1,
			})
		}
	}

	return m.SaveAnalytics(&analytics)
}

// GetAnalytics retrieves analytics for a URL by its shortCodeID
func (m *MongoDB) GetAnalytics(shortCodeID string) (*models.Analytics, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var analytics models.Analytics
	filter := bson.M{"shortCodeId": shortCodeID}
	err := m.analyticsCollection.FindOne(ctx, filter).Decode(&analytics)
	if err != nil {
		return nil, err
	}

	return &analytics, nil
}

// IsValidAPIKey checks if the provided API key is valid by checking the database
func (m *MongoDB) IsValidAPIKey(apiKey string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var foundAPIKey models.APIKey
	filter := bson.M{
		"key":      apiKey,
		"isActive": true,
	}

	// Check if API key exists and is active
	err := m.apiKeysCollection.FindOne(ctx, filter).Decode(&foundAPIKey)
	if err != nil {
		return false
	}

	// Check if API key has expired
	if foundAPIKey.ExpiresAt != nil && time.Now().After(*foundAPIKey.ExpiresAt) {
		return false
	}

	return true
}

// IsAdminAPIKey checks if the provided API key has admin privileges
func (m *MongoDB) IsAdminAPIKey(apiKey string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var foundAPIKey models.APIKey
	filter := bson.M{
		"key":      apiKey,
		"isActive": true,
		"isAdmin":  true,
	}

	// Check if API key exists, is active, and has admin rights
	err := m.apiKeysCollection.FindOne(ctx, filter).Decode(&foundAPIKey)
	if err != nil {
		return false
	}

	// Check if API key has expired
	if foundAPIKey.ExpiresAt != nil && time.Now().After(*foundAPIKey.ExpiresAt) {
		return false
	}

	return true
}

// SaveAPIKey saves an API key to the database
func (m *MongoDB) SaveAPIKey(apiKey *models.APIKey) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if apiKey.ID.IsZero() {
		apiKey.ID = primitive.NewObjectID()
	}

	_, err := m.apiKeysCollection.InsertOne(ctx, apiKey)
	return err
}

// GetAPIKey retrieves an API key by its key string
func (m *MongoDB) GetAPIKey(key string) (*models.APIKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var apiKey models.APIKey
	filter := bson.M{"key": key}
	err := m.apiKeysCollection.FindOne(ctx, filter).Decode(&apiKey)
	if err != nil {
		return nil, err
	}

	return &apiKey, nil
}

// GetAPIKeyByID retrieves an API key by its ID
func (m *MongoDB) GetAPIKeyByID(id primitive.ObjectID) (*models.APIKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var apiKey models.APIKey
	filter := bson.M{"_id": id}
	err := m.apiKeysCollection.FindOne(ctx, filter).Decode(&apiKey)
	if err != nil {
		return nil, err
	}

	return &apiKey, nil
}

// ListAPIKeys returns a list of all API keys
func (m *MongoDB) ListAPIKeys() ([]models.APIKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := m.apiKeysCollection.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var apiKeys []models.APIKey
	if err = cursor.All(ctx, &apiKeys); err != nil {
		return nil, err
	}

	return apiKeys, nil
}

// UpdateAPIKey updates an existing API key
func (m *MongoDB) UpdateAPIKey(apiKey *models.APIKey) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"_id": apiKey.ID}
	update := bson.M{"$set": apiKey}
	_, err := m.apiKeysCollection.UpdateOne(ctx, filter, update)
	return err
}

// DeleteAPIKey deletes an API key by its ID
func (m *MongoDB) DeleteAPIKey(id primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"_id": id}
	_, err := m.apiKeysCollection.DeleteOne(ctx, filter)
	return err
}
