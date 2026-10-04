package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

type Note struct {
	ID        int    `json:"id,omitempty"`
	Title     string `json:"title"`
	Content   string `json:"content"`
	CreatedAt string `json:"created_at,omitempty"`
}

func notesHandler(w http.ResponseWriter, r *http.Request) {
	// SECURITY: Extract UserID from securely validated JWT context
	userID := r.Context().Value("userID").(int)

	path := strings.TrimPrefix(r.URL.Path, "/api/notes")
	if path == "" || path == "/" {
		if r.Method == http.MethodGet {
			getNotes(w, r, userID)
		} else if r.Method == http.MethodPost {
			createNote(w, r, userID)
		} else {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) != 1 {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	noteID, err := strconv.Atoi(parts[0])
	if err != nil {
		http.Error(w, "Invalid note ID", http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodDelete {
		deleteNote(w, r, userID, noteID)
	} else {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func getNotes(w http.ResponseWriter, r *http.Request, userID int) {
	// SECURITY: IDOR Prevention - We only SELECT where user_id matches the authenticated user
	// Parameterized query prevents SQL Injection
	rows, err := db.Query("SELECT id, title, content, created_at FROM notes WHERE user_id = ?", userID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var notes []Note
	for rows.Next() {
		var n Note
		if err := rows.Scan(&n.ID, &n.Title, &n.Content, &n.CreatedAt); err != nil {
			http.Error(w, "Error reading data", http.StatusInternalServerError)
			return
		}
		notes = append(notes, n)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(JSONResponse{Status: "success", Data: notes})
}

func createNote(w http.ResponseWriter, r *http.Request, userID int) {
	var note Note
	if err := json.NewDecoder(r.Body).Decode(&note); err != nil {
		http.Error(w, "Invalid body", http.StatusBadRequest)
		return
	}

	// SECURITY: Strict input validation limits data lengths
	if note.Title == "" || len(note.Title) > 100 {
		http.Error(w, "Invalid title length", http.StatusBadRequest)
		return
	}

	// SECURITY: Parameterized insert entirely mitigates SQL Injection
	result, err := db.Exec("INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)", userID, note.Title, note.Content)
	if err != nil {
		http.Error(w, "Error creating note", http.StatusInternalServerError)
		return
	}

	id, _ := result.LastInsertId()
	note.ID = int(id)
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(JSONResponse{Status: "success", Data: note})
}

func deleteNote(w http.ResponseWriter, r *http.Request, userID int, noteID int) {
	// SECURITY: Strict IDOR Prevention. The WHERE clause includes BOTH id and user_id.
	// This ensures an attacker cannot delete someone else's note by manipulating the ID in the URL.
	result, err := db.Exec("DELETE FROM notes WHERE id = ? AND user_id = ?", noteID, userID)
	if err != nil {
		http.Error(w, "Error deleting note", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Note not found or you do not have permission", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(JSONResponse{Status: "success", Message: "Note deleted"})
}
