package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		var claims *JWTClaims
		_, err := ValidateToken(tokenString)
		if err != nil {
			// Jika token utama expired, coba gunakan refresh token
			refreshToken := r.Header.Get("Refresh-Token")
			if refreshToken == "" {
				http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
				return
			}

			claims, err = ValidateToken(refreshToken)
			if err != nil {
				http.Error(w, "Invalid or expired refresh token", http.StatusUnauthorized)
				return
			}

			if err != nil {
				http.Error(w, "Invalid or expired refresh token", http.StatusUnauthorized)
				return
			}

			// Buat Access Token dan Refresh Token
			accessToken, err := GenerateToken(claims.UserID, claims.UserToken, false)
			if err != nil {
				http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
				return
			}

			var newRefreshToken string
			newRefreshToken, err = GenerateToken(claims.UserID, claims.UserToken, true)
			if err != nil {
				http.Error(w, "Failed to generate refresh token", http.StatusInternalServerError)
				return
			}

			json.NewEncoder(w).Encode(map[string]string{
				"access_token":  accessToken,
				"refresh_token": newRefreshToken,
			})
			return

		}

		next.ServeHTTP(w, r)
	})
}
