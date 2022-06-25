package models

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var (
	accessSigningKey  = []byte("access sig key")
	refreshSigningKey = []byte("refresh sig key")
)

type Tokens struct {
	AccessTokenStr  string
	RefreshTokenStr string
}

type TokenDoc struct {
	UserID           uuid.UUID `bson:"user_id"`
	RefreshTokenHash string    `bson:"token"`
}

type Claims struct {
	UserID   uuid.UUID
	Login    string
	AccToken string
	IsExp    bool
}

func encryptString(s string) (string, error) {
	bs, err := bcrypt.GenerateFromPassword([]byte(s), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(bs), nil
}

func generateTokens(u *UserDoc) (*Tokens, error) {
	claims := jwt.MapClaims{
		"UserID": u.ID.String(),
		"Login":  u.Login,
		"exp":    time.Now().Add(10 * time.Minute).Unix(),
	}

	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(accessSigningKey)
	if err != nil {
		return nil, err
	}

	claims["accToken"] = accessToken
	claims["exp"] = time.Now().Add(72 * time.Hour).Unix()

	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(refreshSigningKey)
	if err != nil {
		return nil, err
	}

	t := &Tokens{
		AccessTokenStr:  accessToken,
		RefreshTokenStr: refreshToken,
	}

	return t, nil
}

func saveRefreshToken(token string, u *UserDoc, tokens *mongo.Collection) error {
	hash, err := encryptString(token)
	if err != nil {
		return err
	}

	t := &TokenDoc{
		UserID:           u.ID,
		RefreshTokenHash: hash,
	}

	if _, err := tokens.UpdateOne(context.TODO(), bson.M{"user_id": u.ID}, bson.M{"$set": t}, options.Update().SetUpsert(true)); err != nil {
		return err
	}

	return nil
}

func UpdateTokens(u *UserDoc, tokens *mongo.Collection) (*Tokens, error) {
	tt, err := generateTokens(u)
	if err != nil {
		return nil, err
	}

	if err = saveRefreshToken(tt.RefreshTokenStr, u, tokens); err != nil {
		return nil, err
	}

	return tt, nil
}

func getClaims(token *jwt.Token) (*Claims, error) {
	c := &Claims{}
	var err error

	claims, ok := token.Claims.(jwt.MapClaims)

	if ok {
		c.Login = claims["Login"].(string)
		if claims["accToken"] != nil {
			c.AccToken = claims["accToken"].(string)
		}
		if c.UserID, err = uuid.Parse(claims["UserID"].(string)); err != nil {
			return nil, err
		}
		c.IsExp = time.Now().Unix()-int64(claims["exp"].(float64)) > 0
	}

	if token.Valid {
		return c, nil
	}

	return c, token.Claims.Valid()
}

func validateToken(tokenStr string, key interface{}) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected method")
		}
		return key, nil
	})

	return token, err
}

func ValidateAccessToken(tokenStr string) (*Claims, error) {
	token, err := validateToken(tokenStr, accessSigningKey)
	if err != nil {
		if err.Error() == "Token is expired" {
			return getClaims(token)
		}
		return nil, err
	}

	return getClaims(token)
}

func ValidateRefreshToken(refToken, accToken, refFromDB string) (*Claims, error) {
	token, err := validateToken(refToken, refreshSigningKey)
	if err != nil {
		return nil, err
	}

	claims, err := getClaims(token)
	if err != nil {
		return nil, err
	}

	if claims.AccToken != accToken {
		return nil, fmt.Errorf("wrong access token")

	}

	err = bcrypt.CompareHashAndPassword([]byte(refFromDB), []byte(refToken))
	if err != nil {
		return nil, err
	}

	return claims, nil
}
