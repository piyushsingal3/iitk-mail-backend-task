package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	Email         string             `json:"email"`
	CreatedAt     time.Time          `json:"created_at"`
	UpdatedAt     time.Time          `json:"updated_at"`
	Password      *string            `json:"password"`
	Token         *string            `json:"token"`
	Refresh_token *string            `json:"refresh_token"`
	ID            primitive.ObjectID `bson:"_id"`
	UserID        string             `json:"user_id"`
}
type Mails struct {
	Senderemail    string    `json:"senderemail"`
	Recipientemail string    `json:"recipientemail"`
	Subject        string    `json:"subject"`
	Body           string    `json:"body"`
	Timestamp      time.Time `json:"timestamp"`
	Attachments    []string  `json:"attachments"`
}
