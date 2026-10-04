package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

// Response structure for standardized JSON responses
type JSONResponse struct {
	Status  string      `json:"status"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

func main() {
	// SECURITY: Use environment variables for configuration, no hardcoded secrets.
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("/health", healthCheckHandler)

	server := &http.Server{
		Addr:    ":" + port,
		Handler: secureHeaders(mux), // Wrap the entire mux with security headers
		// SECURITY: Configure timeouts to mitigate Slowloris attacks.
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	fmt.Printf("Starting secure API on port %s\n", port)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	// SECURITY: Only allow GET methods for this endpoint.
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	response := JSONResponse{Status: "success", Message: "API is healthy"}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// secureHeaders is a middleware that adds standard security headers to every response.
func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// SECURITY: Prevent MIME-sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// SECURITY: Prevent Clickjacking
		w.Header().Set("X-Frame-Options", "DENY")
		// SECURITY: Enable Cross-Site Scripting (XSS) filter built into most browsers
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		
		// Call the next handler
		next.ServeHTTP(w, r)
	})
}
