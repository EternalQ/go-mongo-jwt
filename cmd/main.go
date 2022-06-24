package main

import (
	"context"
	"go-mongo-jwt/models"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

var (
	users  *mongo.Collection
	tokens *mongo.Collection
)

func main() {
	client, err := getClient("mongodb://localhost:27017")
	if err != nil {
		log.Fatal(err.Error())
	}
	defer client.Disconnect(context.TODO())

	users = client.Database("test-task").Collection("users")
	tokens = client.Database("test-task").Collection("tokens")

	if result := users.FindOne(context.Background(), bson.D{}); result.Err() == mongo.ErrNoDocuments {
		userPreset()
	}

	r := gin.Default()

	r.GET("/signin/:id", handleSignIn)
	r.GET("/refresh", handleRefresh)

	r.Run(":8081")
}

func getClient(connectionURI string) (*mongo.Client, error) {
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(connectionURI))
	if err != nil {
		return nil, err
	}

	err = client.Ping(context.Background(), readpref.Primary())
	if err != nil {
		return nil, err
	}

	return client, nil
}

func userPreset() {
	users.Drop(context.Background())
	models.NewUser("user1", users)
	models.NewUser("uuSer", users)
	models.NewUser("uniqU", users)
	models.NewUser("super", users)
}

func handleSignIn(c *gin.Context) {
	rawID := c.Param("id")
	u := &models.UserDoc{}

	id, err := uuid.Parse(rawID)
	if err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	if err := users.FindOne(context.Background(), bson.D{{"_id", id}}).Decode(u); err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	tt, err := models.UpdateTokens(u, tokens)
	if err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	c.SetCookie("reftoken", tt.SigRefreshToken, 72*60*60, "", "", false, true)

	c.JSON(200, tt.SigAccessToken)
}

func handleRefresh(c *gin.Context) {
	// check access token
	accessToken := c.GetHeader("Authorization")[7:]
	if accessToken == "" {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	accClaims, err := models.ValidateAccessToken(accessToken)
	if !accClaims.IsExp {
		c.AbortWithStatusJSON(http.StatusBadRequest, "access token still valid")
		return
	}
	if err != nil && err.Error() != "Token is expired" {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	// if expired validate refresh token...
	refreshToken, err := c.Cookie("reftoken")
	if err != nil {
		c.AbortWithError(http.StatusUnauthorized, err)
		return
	}

	refClaims, err := models.ValidateRefreshToken(refreshToken, accClaims.RefHash)
	if err != nil {
		c.AbortWithError(http.StatusUnauthorized, err)
		return
	}

	// and generate new pair
	if err := users.FindOne(context.Background(), bson.D{{"_id", refClaims.UserID}}).Decode(refClaims); err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	u := &models.UserDoc{
		ID:    refClaims.UserID,
		Login: refClaims.Login,
	}
	tt, err := models.UpdateTokens(u, tokens)
	if err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	c.SetCookie("reftoken", tt.SigRefreshToken, 72*60*60, "", "", false, true)

	c.JSON(200, tt.SigAccessToken)
}
