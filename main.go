package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"

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

// Structure for alerts dealt with in the alerts endpoint
type Alert struct {
	Id        int    `json:"id"`
	Type      string `json:"type"`
	Message   string `json:"message"`
	Fatal     bool   `json:"is_fatal"`
	Timestamp string `json:"timestamp"`
}

func main() {
	admin_username := os.Getenv("admin_username")
	admin_password := os.Getenv("admin_password")
	//Initialize SQLite database and start router
	createDatabaseTables(admin_password, admin_username)
	router := mux.NewRouter()
	router.HandleFunc("/v1/analytics", analyticsEndpoint).Methods("POST")
	router.HandleFunc("/v1/analytics/{collection}", analyticsEndpoint).Methods("GET")
	router.HandleFunc("/v1/alerts", alertsEndpoint).Methods("POST")

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
		username TEXT NOT NULL,
		password TEXT NOT NULL,
		collections BLOB
	)`)
	if err != nil {
		log.Fatal(err)
	}

	// Insert data into the SQLite table
	_, err = db.Exec("INSERT INTO users (username,password) VALUES (?, ?)", admin_username, admin_password)
	if err != nil {
		log.Fatal(err)
	}

	// Create table for alerts
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        type TEXT NOT NULL,
						message TEXT,
						fatal BOOLEAN NOT NULL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )`)
	if err != nil {
		log.Fatal(err)
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
	if !validateUser(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method == http.MethodPost {
		createData(w, r)
	}
	if r.Method == http.MethodGet {
		getData(w, r)
	}
}

// Endpoint for alerts
func alertsEndpoint(w http.ResponseWriter, r *http.Request) {
	if !validateUser(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method == http.MethodPost {
		createAlert(w, r)
	}
}

// function to create an alert inside of the alerts table
func createAlert(w http.ResponseWriter, r *http.Request) {
	var alert Alert
	err := json.NewDecoder(r.Body).Decode(&alert)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	db, err := sql.Open("sqlite3", "./data/test-database.db")
	if err != nil {
		log.Fatal(err)
	}

	if len(alert.Type) == 0 || len(alert.Message) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// Insert data into the SQLite table
	_, err = db.Exec("INSERT INTO alerts (type, message, fatal) VALUES (?, ?, ?)", alert.Type, alert.Message, alert.Fatal)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	w.WriteHeader(http.StatusCreated)
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
	println(credentials[0])
	println(credentials[1])
	username := credentials[0]
	password := credentials[1]

	db, err := sql.Open("sqlite3", "./data/test-database.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	var userID int
	err = db.QueryRow("SELECT id FROM users WHERE username = ? AND password = ?", username, password).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows { // No rows were returned
			return false
		} else {
			log.Fatal(err)
		}
	}

	return true
}
