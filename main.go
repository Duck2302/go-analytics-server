package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
)

// Structure for data dealt with in the analytics endpoints
type Data struct {
	Id         int    `json:"id"`
	Type       string `json:"type"`
	Source     string `json:"source"`
	Collection string `json:"collection"`
	Data       string `json:"data"`
	Timestamp  string `json:"timestamp"`
}

type User struct {
	Id       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func main() {
	admin_username := os.Getenv("admin_username")
	admin_password := os.Getenv("admin_password")
	//Initialize SQLite database and start router
	createDatabaseTables(admin_password, admin_username)
	router := mux.NewRouter()
	router.HandleFunc("/v1/analytics", analyticsEndpoint).Methods("POST")
	router.HandleFunc("/v1/analytics/{collection}", analyticsEndpoint).Methods("GET")
	router.HandleFunc("/v1/api-key/generate", generateApiKey).Methods("GET")
	router.HandleFunc("/v1/api-key/delete/{id}", deleteApiKey).Methods("DELETE")
	router.HandleFunc("/v1/api-key/regenerate/{id}", regenerateApiKey).Methods("PUT")
	router.HandleFunc("/v1/users/create", createUser).Methods("POST")
	router.HandleFunc("/v1/users/delete/{id}", deleteUser).Methods("DELETE")

	log.Printf("Starting server on Port 5000")
	log.Fatal(http.ListenAndServe(":5000", router))
}

func createDatabaseTables(admin_password string, admin_username string) {
	db, err := sql.Open("sqlite3", "./data/test-database.db")
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL
	)`)
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS apikeys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		api_key TEXT NOT NULL,
		user_id INTEGER,
		FOREIGN KEY(user_id) REFERENCES users(id)
	)`)
	if err != nil {
		log.Fatal(err)
	}

	var userID int
	err = db.QueryRow("SELECT id FROM users WHERE username = ? AND password = ?", admin_username, admin_password).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows { // No rows were returned
			_, err = db.Exec("INSERT INTO users (username,password) VALUES (?, ?)", admin_username, admin_password)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			log.Fatal(err)
		}
	}

	// Create table for analytics
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS analytics (
						id INTEGER PRIMARY KEY AUTOINCREMENT,
						type TEXT NOT NULL,
						source TEXT,
						collection TEXT,
						data TEXT,
						timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
					)`)
	if err != nil {
		log.Fatal(err)
	}

	defer db.Close()
}

// Endpoint for analytics with differentiation between POST and GET
func analyticsEndpoint(w http.ResponseWriter, r *http.Request) {
	if !validateApiKey(w, r) {
		return
	}
	if r.Method == http.MethodPost {
		createData(w, r)
	}
	if r.Method == http.MethodGet {
		getData(w, r)
	}
}

// function to create data in the analytics table
func createData(w http.ResponseWriter, r *http.Request) {
	var data Data
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(data.Type) == 0 || len(data.Source) == 0 || len(data.Collection) == 0 || len(data.Data) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	db, err := sql.Open("sqlite3", "./data/test-database.db")
	if err != nil {
		log.Fatal(err)
	}

	// Insert data into the SQLite table
	_, err = db.Exec("INSERT INTO analytics (type,source, collection, data) VALUES (?, ?, ?,?)", data.Type, data.Source, data.Collection, data.Data)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	w.WriteHeader(http.StatusCreated)
}

// function to get data as a list by collection name
func getData(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	collection := vars["collection"]
	if collection == "" {
		http.Error(w, "Collection parameter is missing", http.StatusBadRequest)
		return
	}

	db, err := sql.Open("sqlite3", "./data/test-database.db")
	if err != nil {
		log.Fatal(err)
	}
	rows, err := db.Query("SELECT * FROM analytics WHERE collection = ?", collection)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	var results []Data
	for rows.Next() {
		var d Data
		err := rows.Scan(&d.Id, &d.Type, &d.Collection, &d.Data, &d.Timestamp)
		if err != nil {
			log.Fatal(err)
		}
		results = append(results, d)
	}
	if len(results) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(results)
}

func validateUser(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	credentials := strings.Split(auth, " ")
	username := credentials[0]
	password := credentials[1]

	db, err := sql.Open("sqlite3", "./data/test-database.db")
	if err != nil {
		log.Fatal(err)
	}

	var userID int
	err = db.QueryRow("SELECT id FROM users WHERE username = ? AND password = ?", username, password).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows { // No rows were returned
			return false
		} else {
			log.Fatal(err)
		}
	}
	defer db.Close()

	return true
}

func generateApiKey(w http.ResponseWriter, r *http.Request) {
	if !validateUser(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	db, err := sql.Open("sqlite3", "./data/test-database.db")
	if err != nil {
		log.Fatal(err)
	}

	auth := r.Header.Get("Authorization")
	credentials := strings.Split(auth, " ")
	username := credentials[0]

	// Retrieve the user ID for the given username
	var userId int
	row := db.QueryRow("SELECT id FROM users WHERE username = ?", username)
	row_err := row.Scan(&userId)
	if row_err != nil {
		log.Fatal(err)
	}

	apiKey := uuid.New().String()

	// Insert the new API key with the user_id
	_, err = db.Exec("INSERT INTO apikeys (api_key, user_id) VALUES (?, ?)", apiKey, userId)
	if err != nil {
		log.Fatal(err)
	}

	defer db.Close()

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"api_key": apiKey})
}

func deleteApiKey(w http.ResponseWriter, r *http.Request) {
	if !validateUser(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	db, err := sql.Open("sqlite3", "./data/test-database.db")
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec("DELETE FROM apikeys WHERE id = ?", id)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	w.WriteHeader(http.StatusOK)
}

func regenerateApiKey(w http.ResponseWriter, r *http.Request) {
	if !validateUser(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	db, err := sql.Open("sqlite3", "./data/test-database.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Generate a new API key
	newApiKey := uuid.New().String()

	// Update the existing API key with the new one for the given id
	_, err = db.Exec("UPDATE apikeys SET api_key = ? WHERE id = ?", newApiKey, id)
	if err != nil {
		log.Fatal(err)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"api_key": newApiKey})
}
func validateApiKey(w http.ResponseWriter, r *http.Request) bool {
	apiKey := r.Header.Get("API-Key")
	if apiKey == "" {
		http.Error(w, "API key is required", http.StatusUnauthorized)
		return false
	}
	db, err := sql.Open("sqlite3", "./data/test-database.db")
	if err != nil {
		log.Fatal(err)
	}

	var userID int
	err = db.QueryRow("SELECT user_id FROM apikeys WHERE api_key = ?", apiKey).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows { // No rows were returned
			http.Error(w, "API key is invalid", http.StatusUnauthorized)
			return false
		} else {
			log.Fatal(err)
		}
	}
	defer db.Close()

	return true
}

func createUser(w http.ResponseWriter, r *http.Request) {
	if !validateApiKey(w, r) {
		return
	}
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(user.Username) == 0 || len(user.Password) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	db, err := sql.Open("sqlite3", "./data/test-database.db")
	if err != nil {
		log.Fatal(err)
	}

	// Insert data into the SQLite table
	_, err = db.Exec("INSERT INTO users (username,password) VALUES (?, ?)", user.Username, user.Password)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	w.WriteHeader(http.StatusCreated)

}

func deleteUser(w http.ResponseWriter, r *http.Request) {
	if !validateApiKey(w, r) {
		return
	}
	vars := mux.Vars(r)
	id := vars["id"]

	db, err := sql.Open("sqlite3", "./data/test-database.db")
	if err != nil {
		log.Fatal(err)
	}
	_, err = db.Exec("DELETE FROM users where id=?", id)
	if err != nil {
		log.Fatal(err)
	}
	_, err = db.Exec("DELETE FROM apikeys WHERE user_id = ?", id)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	w.WriteHeader(http.StatusOK)
}
