package models

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/mongo"
)

type UserDoc struct {
	ID    uuid.UUID `bson:"_id"`
	Login string    `bson:"login"`
}

func NewUser(login string, users *mongo.Collection) error {
	id, err := uuid.NewUUID()
	if err != nil {
		return err
	}

	u := &UserDoc{
		ID:    id,
		Login: login,
	}

	_, err = users.InsertOne(context.Background(), u)
	fmt.Printf("added user %s\n", id)

	return err
}
