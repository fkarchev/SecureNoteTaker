package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// SECURITY: In production, load this from a secure secrets manager.
var jwtKey = []byte(getEnvOrDefault("JWT_SECRET", "super_secret_dev_key"))

func getEnvOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	UserID int `json:"user_id"`
	jwt.RegisteredClaims
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds Credentials
	// SECURITY: Strict input decoding.
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// SECURITY: Validate input length (prevent DoS with huge inputs or bad data)
	if len(creds.Username) < 3 || len(creds.Username) > 50 || len(creds.Password) < 8 {
		http.Error(w, "Invalid username or password criteria (min 8 chars password)", http.StatusBadRequest)
		return
	}

	// SECURITY: Hash password using bcrypt. NEVER store plaintext.
	// bcrypt automatically handles salting. DefaultCost is currently 10.
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// SECURITY: Parameterized query to prevent SQL Injection
	_, err = db.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", creds.Username, string(hashedPassword))
	if err != nil {
		// SECURITY: Log actual error internally, but return generic error to client to prevent information leakage
		http.Error(w, "Username already exists or server error", http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(JSONResponse{Status: "success", Message: "User created"})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds Credentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var storedHash string
	var userID int
	// SECURITY: Parameterized query
	err := db.QueryRow("SELECT id, password_hash FROM users WHERE username = ?", creds.Username).Scan(&userID, &storedHash)
	if err != nil {
		// SECURITY: Prevent user enumeration by giving a generic message (don't reveal if user exists)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// SECURITY: Securely compare hash with provided password
	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(creds.Password)); err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// SECURITY: Generate short-lived JWT token (1 hour)
	expirationTime := time.Now().Add(1 * time.Hour)
	claims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(JSONResponse{Status: "success", Data: map[string]string{"token": tokenString}})
}

// AuthMiddleware extracts JWT and securely verifies it
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing authorization token", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
			return
		}

		tokenStr := parts[1]
		claims := &Claims{}

		// SECURITY: Parse and mathematically validate the token signature using our secret key
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// SECURITY: Pass the securely authenticated user ID down the context
		ctx := context.WithValue(r.Context(), "userID", claims.UserID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
