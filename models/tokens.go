package models

import (
	"context"
	"crypto/sha1"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/mongo"
)

var (
	accessSigningKey  = []byte("access sig key")
	refreshSigningKey = []byte("refresh sig key")
)

type Tokens struct {
	SigAccessToken  string
	SigRefreshToken string
}

type TokenDoc struct {
	UserID           uuid.UUID `bson:"user_id"`
	RefreshTokenHash string    `bson:"token"`
}

type Claims struct {
	UserID  uuid.UUID
	Login   string
	RefHash string
	IsExp   bool
}

func encryptString(s string) string {
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}

func generateTokens(u *UserDoc) (*Tokens, error) {
	// &Claims{
	// 	UserID: u.ID.String(),
	// 	Login:  u.Login,
	// 	StandardClaims: jwt.StandardClaims{
	// 		ExpiresAt: time.Now().Add(100 * time.Second).Unix(),
	// 	},
	// }

	claims := jwt.MapClaims{
		"UserID": u.ID.String(),
		"Login":  u.Login,
		"exp":    time.Now().Add(72 * time.Hour).Unix(),
	}

	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(refreshSigningKey)
	if err != nil {
		return nil, err
	}

	refHash := encryptString(refreshToken)
	claims["refHash"] = refHash
	claims["exp"] = time.Now().Add(10 * time.Minute).Unix()

	// fmt.Printf("ref: %v\nhsh: %v\n", refreshToken, refHash)

	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(accessSigningKey)
	if err != nil {
		return nil, err
	}

	t := &Tokens{
		SigAccessToken:  accessToken,
		SigRefreshToken: refreshToken,
	}

	return t, nil
}

func saveRefreshToken(token string, u *UserDoc, tokens *mongo.Collection) error {
	hash := encryptString(token)

	t := &TokenDoc{
		UserID:           u.ID,
		RefreshTokenHash: hash,
	}

	if _, err := tokens.InsertOne(context.Background(), t); err != nil {
		return err
	}

	return nil
}

func UpdateTokens(u *UserDoc, tokens *mongo.Collection) (*Tokens, error) {
	tt, err := generateTokens(u)
	if err != nil {
		return nil, err
	}

	if err = saveRefreshToken(tt.SigRefreshToken, u, tokens); err != nil {
		return nil, err
	}

	return tt, nil
}

func getClaims(token *jwt.Token) (*Claims, error) {
	c := &Claims{}
	var err error

	claims, ok := token.Claims.(jwt.MapClaims)
	// fmt.Printf("%v\n", token.Claims.Valid().Error())

	if ok {
		c.Login = claims["Login"].(string)
		if claims["refHash"] != nil {
			c.RefHash = claims["refHash"].(string)
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

func ValidateRefreshToken(tokenStr, hash string) (*Claims, error) {
	token, err := validateToken(tokenStr, refreshSigningKey)
	if err != nil {
		return nil, err
	}

	newhash := encryptString(tokenStr)
	// fmt.Printf("ref: %v\nold: %v\nnew: %v\n", tokenStr, hash, newhash)
	if newhash != hash {
		return nil, fmt.Errorf("wrong access token")
	}

	return getClaims(token)
}
