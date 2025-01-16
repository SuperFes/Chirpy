package auth

import (
	"crypto/rand"
	"encoding/hex"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"strings"
	"time"
)

func HashPassword(password string) ([]byte, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 14)

	if err != nil {
		return []byte{}, err
	}

	return hash, nil
}

func ComparePassword(hashedPassword, password string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))

	if err != nil {
		return err
	}

	return nil
}

func MakeToken(userID uuid.UUID, tokenSecret string, expiresIn int) (string, error) {
	expires := time.Hour

	log.Println(userID, tokenSecret, expiresIn)

	if expiresIn > 0 {
		expiresIn = time.Now().Add(time.Second * time.Duration(expiresIn)).Second()
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userID": userID,
		"exp":    time.Now().Add(expires).Unix(),
	})

	tokenString, err := token.SignedString([]byte(tokenSecret))

	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func ValidateToken(tokenString, tokenSecret string) (uuid.UUID, error) {
	log.Println(tokenString, tokenSecret)

	token, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(tokenSecret), nil
	}, jwt.WithLeeway(5*time.Second))

	if err != nil {
		log.Println(token, err)
		return uuid.UUID{}, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userID, err := uuid.Parse(claims["userID"].(string))

		log.Println("claims", claims)

		log.Println(userID, err)

		if err != nil {
			return uuid.UUID{}, err
		}

		exp := time.Unix(int64(claims["exp"].(float64)), 0)

		if exp.Before(time.Now()) {
			return uuid.UUID{}, jwt.ErrTokenExpired
		}

		log.Println("exp", exp)
		log.Println("time", time.Now())
		log.Println("user", userID)

		return userID, nil
	} else {
		log.Println("claims", claims)
		log.Println("ok", ok)
		return uuid.UUID{}, err
	}
}

func GetBearerToken(headers http.Header) (string, error) {
	authHeader := strings.Replace(headers.Get("Authorization"), "Bearer ", "", 1)

	if authHeader == "" {
		return "", nil
	}

	return authHeader, nil
}

func MakeRefreshToken() (string, error) {
	b := make([]byte, 32)

	_, err := rand.Read(b)

	if err != nil {
		return "", err
	}

	h := hex.EncodeToString(b)

	return h, nil
}

func GetAPIKey(headers http.Header) (string, error) {
	authHeader := strings.Replace(headers.Get("Authorization"), "ApiKey ", "", 1)

	if authHeader == "" {
		return "", nil
	}

	return authHeader, nil
}
