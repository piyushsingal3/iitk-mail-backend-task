package store

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoStore struct {
	UsersCollection *mongo.Collection
	EmailCollection *mongo.Collection
}

func NewMongoStore() *MongoStore {
	return &MongoStore{}
}
func (m *MongoStore) OpenConnectionWithMongoDB(connectionString, databaseName string) error {
	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(connectionString))
	if err != nil {
		return fmt.Errorf("failed to connect to MongoDB: %v", err)
	}

	err = client.Ping(context.TODO(), nil)
	if err != nil {
		return fmt.Errorf("failed to ping MongoDB: %v", err)
	}

	db := client.Database(databaseName)

	m.UsersCollection = db.Collection("Users")
	m.EmailCollection = db.Collection("Emails")

	return nil
}
