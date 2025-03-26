package main

import (
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func Find(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

// Update entry in User map
func updateUserInfo(values interface{}, field string, value string) interface{} {
	log.Debug().Str("field", field).Str("value", value).Msg("User info updated")
	values.(Values).m[field] = value
	return values
}

// webhook for regular messages
func callHook(myurl string, payload map[string]string, id int) {
	log.Info().Str("url", myurl).Msg("Sending POST to client " + strconv.Itoa(id))

	// Log the payload map
	log.Debug().Msg("Payload:")
	for key, value := range payload {
		log.Debug().Str(key, value).Msg("")
	}

	_, err := clientHttp[id].R().SetFormData(payload).Post(myurl)
	if err != nil {
		log.Debug().Str("error", err.Error())
	}
}

// webhook for messages with file attachments
func callHookFile(myurl string, payload map[string]string, id int, file string) error {
	log.Info().Str("file", file).Str("url", myurl).Msg("Sending POST")

	resp, err := clientHttp[id].R().
		SetFiles(map[string]string{
			"file": file,
		}).
		SetFormData(payload).
		Post(myurl)

	if err != nil {
		log.Error().Err(err).Str("url", myurl).Msg("Failed to send POST request")
		return fmt.Errorf("failed to send POST request: %w", err)
	}

	// Optionally, you can log the response status
	log.Info().Int("status", resp.StatusCode()).Msg("POST request completed")

	return nil
}

// HashPassword mengubah password menjadi hash
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

// CheckPassword membandingkan password dengan hash
func CheckPassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

// Struktur Payload Token
type JWTClaims struct {
	UserID    int    `json:"user_id"`
	UserToken string `json:"user_token"`
	jwt.RegisteredClaims
}

// Fungsi untuk membuat JWT Token
func GenerateToken(userID int, userToken string, isRefresh bool) (string, error) {

	expirationMinutes, err := strconv.Atoi(os.Getenv("JWT_EXPIRATION"))
	if err != nil {
		log.Error().Err(err).Msg("Invalid JWT_EXPIRATION value")
		return "", fmt.Errorf("invalid JWT_EXPIRATION value: %w", err)
	}
	expirationTime := time.Now().Add(time.Minute * time.Duration(expirationMinutes)) // Default 15 menit untuk Access Token
	if isRefresh {
		refreshHours, err := strconv.Atoi(os.Getenv("JWT_REFRESH_EXPIRATION"))
		if err != nil {
			log.Error().Err(err).Msg("Invalid JWT_REFRESH_EXPIRATION value")
			return "", fmt.Errorf("invalid JWT_REFRESH_EXPIRATION value: %w", err)
		}
		expirationTime = time.Now().Add(time.Minute * time.Duration(refreshHours)) // 1 jam untuk Refresh Token
	}

	claims := &JWTClaims{
		UserID:    userID,
		UserToken: userToken,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(os.Getenv("JWT_SECRET")))
}

// Fungsi untuk validasi JWT Token
func ValidateToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, err
}

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func RandomString(length int) string {
	rand.Seed(time.Now().UnixNano()) // Seed untuk mendapatkan hasil acak yang berbeda setiap eksekusi
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}
