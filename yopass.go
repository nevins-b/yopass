package main

import (
	"crypto/tls"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/bradfitz/gomemcache/memcache"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/satori/go.uuid"
)

// Database interface
type Database interface {
	Get(key string) ([]byte, error)
	Set(key string, value []byte, expiration int32) error
	Delete(key string) error
}

type memcached struct {
	Client *memcache.Client
}

// Get key in memcache
func (m memcached) Get(key string) ([]byte, error) {

	r, err := m.Client.Get(key)
	if err != nil {
		return []byte{}, err
	}
	return r.Value, nil
}

// Store key in memcache
func (m memcached) Set(key string, value []byte, expiration int32) error {
	return m.Client.Set(&memcache.Item{
		Key:        key,
		Value:      value,
		Expiration: expiration})
}

func (m memcached) Delete(key string) error {
	return m.Client.Delete(key)
}

// validExpiration validates that expiration is ether
// 3600(1hour), 86400(1day) or 604800(1week)
func validExpiration(expiration int32) bool {
	for _, ttl := range []int32{3600, 86400, 604800} {
		if ttl == expiration {
			return true
		}
	}
	return false
}

// Handle requests for saving secrets
func saveHandler(response http.ResponseWriter, request *http.Request,
	db Database) {
	response.Header().Set("Content-type", "application/json")

	if request.Method != "POST" {
		http.Error(response,
			`{"message": "Bad Request, see https://github.com/jhaals/yopass for more info"}`,
			http.StatusBadRequest)
		return
	}

	decoder := json.NewDecoder(request.Body)
	var secret struct {
		Message    string `json:"secret"`
		Nonce      string `json:"nonce"`
		Expiration int32  `json:"expiration"`
	}
	err := decoder.Decode(&secret)
	if err != nil {
		http.Error(response, `{"message": "Unable to parse json"}`, http.StatusBadRequest)
		return
	}

	if validExpiration(secret.Expiration) == false {
		http.Error(response, `{"message": "Invalid expiration specified"}`, http.StatusBadRequest)
		return
	}

	message, _ := json.Marshal(&secret)
	if len(message) > 10000 {
		http.Error(response, `{"message": "Message is too long"}`, http.StatusBadRequest)
		return
	}

	// Generate new UUID and store secret in memcache with specified expiration
	uuid := uuid.NewV4()
	err = db.Set(uuid.String(), message, secret.Expiration)
	if err != nil {
		http.Error(response, `{"message": "Failed to store secret in database"}`, http.StatusInternalServerError)
		return
	}

	resp := map[string]string{"key": uuid.String(), "message": "secret stored"}
	jsonData, _ := json.Marshal(resp)
	response.Write(jsonData)
}

// Handle GET requests
func getHandler(response http.ResponseWriter, request *http.Request, db Database) {
	response.Header().Set("Content-type", "application/json")
	data, err := db.Get(mux.Vars(request)["uuid"])
	if err != nil {
		if err.Error() == "memcache: cache miss" {
			http.Error(response, `{"message": "Secret not found"}`, http.StatusNotFound)
			return
		}
		log.Println(err)
		http.Error(response, `{"message": "Unable to receive secret from database"}`, http.StatusInternalServerError)
		return
	}

	// Delete secret from memcached
	db.Delete(mux.Vars(request)["uuid"])

	var secret struct {
		Message    string `json:"secret"`
		Nonce      string `json:"nonce"`
		Expiration int32  `json:"expiration"`
	}

	err = json.Unmarshal(data, &secret)
	if err != nil {
		http.Error(response, `{"message": "Unable to decode secret"}`, http.StatusInternalServerError)
		return
	}

	var resp struct {
		Secret  string `json:"secret"`
		Nonce   string `json:"nonce"`
		Message string `json:"message"`
	}

	resp.Secret = secret.Message
	resp.Nonce = secret.Nonce
	resp.Message = "OK"

	jsonData, _ := json.Marshal(resp)
	response.Write(jsonData)
}

// Handle HEAD requests for message status.
// return 200 if message exist in memcache or 404 if not
func messageStatus(response http.ResponseWriter, request *http.Request, db Database) {
	_, err := db.Get(mux.Vars(request)["uuid"])
	response.Header().Set("Connection", "close")
	if err != nil {
		log.Println(err)
		response.WriteHeader(http.StatusNotFound)
		return
	}
}

func main() {
	if os.Getenv("MEMCACHED") == "" {
		log.Println("MEMCACHED environment variable must be specified")
		os.Exit(1)
	}
	mc := memcached{memcache.New(os.Getenv("MEMCACHED"))}

	mx := mux.NewRouter()
	// GET secret
	mx.HandleFunc("/secret/{uuid:(?:[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12})}",
		func(response http.ResponseWriter, request *http.Request) {
			getHandler(response, request, mc)
		}).Methods("GET")
	// Check secret status
	mx.HandleFunc("/secret/{uuid:(?:[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12})}",
		func(response http.ResponseWriter, request *http.Request) {
			messageStatus(response, request, mc)
		}).Methods("HEAD")
	// Save secret
	mx.HandleFunc("/secret", func(response http.ResponseWriter, request *http.Request) {
		saveHandler(response, request, mc)
	}).Methods("POST")
	// Serve static files
	mx.PathPrefix("/").Handler(http.FileServer(http.Dir("public")))

	log.Println("Starting yopass. Listening on port 1337")
	if os.Getenv("TLS_CERT") != "" && os.Getenv("TLS_KEY") != "" {
		// Configure TLS with sane ciphers
		config := &tls.Config{MinVersion: tls.VersionTLS12}
		server := &http.Server{Addr: ":1337",
			Handler: handlers.LoggingHandler(os.Stdout, mx), TLSConfig: config}
		log.Fatal(server.ListenAndServeTLS(os.Getenv("TLS_CERT"), os.Getenv("TLS_KEY")))
	} else {
		log.Fatal(http.ListenAndServe(":1337", handlers.LoggingHandler(os.Stdout, mx)))
	}
}
