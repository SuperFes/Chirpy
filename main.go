package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/SuperFes/Chripy/internal/auth"
	"github.com/SuperFes/Chripy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
)

import _ "github.com/lib/pq"

type apiConfig struct {
	fileServerHits atomic.Int32
	dbUri          string
	platform       string
	db             *database.Queries
	secret         string
	polkaApi       string
}

func (c *apiConfig) fileServerInc(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		c.fileServerHits.Add(1)

		hits := strconv.Itoa(c.getHits())

		fmt.Println("Hits: " + hits)

		return next
	}(next)
}

func (c *apiConfig) resetHits() {
	c.fileServerHits.Store(0)
}

func (c *apiConfig) getHits() int {
	return int(c.fileServerHits.Load())
}

func AddHit(config *apiConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		config.fileServerHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func ResetHits(config *apiConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if config.platform == "Development" {
			config.db.DeleteUsers(r.Context())
			config.db.DeleteChirps(r.Context())
			config.resetHits()
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		} else {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Forbidden"))
		}
	}
}

func Metrics(config *apiConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hits := strconv.Itoa(config.getHits())

		fmt.Println("Hits: " + hits)

		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)

		w.Write([]byte("<html>" +
			"<body>" +
			"<h1>Welcome, Chirpy Admin</h1>" +
			"<p>Chirpy has been visited " + hits + " times!</p>" +
			"</body>" +
			"</html>"))
	}
}

func HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

type chirp struct {
	Body   string    `json:"body"`
	UserID uuid.UUID `json:"user_id"`
}

func encodeJSON(w http.ResponseWriter, data interface{}) {
	// Encode the JSON
	encodedData, err := json.Marshal(data)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Println(err)

		return
	}

	compact := &bytes.Buffer{}

	err = json.Compact(compact, encodedData)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Println(err)

		return
	}

	w.Header().Set("Content-Type", "application/json")

	fmt.Println(compact.String())
	w.Write(compact.Bytes())
}

func decodeJSON(request *http.Request) (chirp, error) {
	// Decode the JSON
	var c chirp

	body, err := io.ReadAll(request.Body)

	if err != nil {
		return chirp{}, err
	}

	err = json.Unmarshal(body, &c)

	if err != nil {
		return chirp{}, err
	}

	return c, nil
}

func profanityCheck(body string) string {
	profanities := make([]string, 0)

	profanities = append(profanities, "kerfuffle")
	profanities = append(profanities, "sharbert")
	profanities = append(profanities, "fornax")

	bodyParts := strings.Fields(body)
	newBody := make([]string, 0)

	for _, bodyPart := range bodyParts {
		match := false

		for _, profanity := range profanities {
			if strings.ToLower(bodyPart) == profanity {
				match = true
			}
		}

		if match {
			newBody = append(newBody, "****")
		} else {
			newBody = append(newBody, bodyPart)
		}
	}

	return strings.Join(newBody, " ")
}

func ChirpCheck(config *apiConfig) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := auth.GetBearerToken(r.Header)

		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			encodeJSON(w, map[string]string{"error": "Unauthorized"})
			return
		}

		//userId, err := config.db.GetUserFromToken(r.Context(), token)
		//
		//if err != nil {
		userId, err := auth.ValidateToken(token, config.secret)

		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			encodeJSON(w, map[string]string{"error": "Unauthorized"})
			log.Println("ChirpCheck", err)
			return
		}
		//}

		chirp, err := decodeJSON(r)

		log.Println("chirp", chirp)

		if err != nil {
			fmt.Println(err)

			w.WriteHeader(http.StatusBadRequest)
			encodeJSON(w, map[string]string{"error": "Something went wrong"})
			return
		}

		if userId == uuid.Nil {
			w.WriteHeader(http.StatusUnauthorized)
			log.Println("ChirpCheck", userId, chirp.UserID)
			encodeJSON(w, map[string]string{"error": "Unauthorized"})
			return
		}

		body := profanityCheck(chirp.Body)

		if len(body) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			encodeJSON(w, map[string]string{"error": "Chirp is not provided"})
			return
		}

		log.Println(body, len(body))

		if len(body) > 140 {
			w.WriteHeader(http.StatusBadRequest)
			encodeJSON(w, map[string]string{"error": "Chirp is too long"})
			return
		}

		newChirp, err := config.db.CreateChirp(r.Context(), database.CreateChirpParams{
			UserID: userId,
			Body:   body,
		})

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			encodeJSON(w, map[string]string{"error": "Internal server error"})
			log.Println(err)
			return
		}

		w.WriteHeader(http.StatusCreated)
		encodeJSON(w, map[string]string{
			"id":         newChirp.ID.String(),
			"body":       newChirp.Body,
			"user_id":    newChirp.UserID.String(),
			"created_at": newChirp.CreatedAt.String(),
			"updated_at": newChirp.UpdatedAt.String(),
		})
	}
}

type newUser struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func CreateUser(config *apiConfig) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var inUser newUser

		body, err := io.ReadAll(r.Body)

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Println(err)

			return
		}

		err = json.Unmarshal(body, &inUser)

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Println(err)

			return
		}

		if len(inUser.Email) == 0 || len(inUser.Password) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			encodeJSON(w, map[string]string{"error": "Email or password is not provided"})

			return
		}

		pass, err := auth.HashPassword(inUser.Password)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Println(err)

			return
		}

		user, err := config.db.CreateUser(r.Context(), database.CreateUserParams{
			Email:    inUser.Email,
			Password: string(pass),
		})

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Println(err)

			return
		}

		outUser := map[string]interface{}{
			"id":            user.ID,
			"created_at":    user.CreatedAt,
			"updated_at":    user.UpdatedAt,
			"email":         user.Email,
			"is_chirpy_red": user.IsChirpyRed,
		}
		w.WriteHeader(http.StatusCreated)
		encodeJSON(w, outUser)
	}
}

func Chirps(config *apiConfig) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		author_id, err := uuid.Parse(r.URL.Query().Get("author_id"))
		sortOrder := r.URL.Query().Get("sort")

		//token, err := auth.GetBearerToken(r.Header)
		//
		//if err != nil {
		//	w.WriteHeader(http.StatusUnauthorized)
		//	encodeJSON(w, map[string]string{"error": "Unauthorized"})
		//	return
		//}
		//
		//_, err = auth.ValidateToken(token, config.secret)
		//
		//if err != nil {
		//	w.WriteHeader(http.StatusUnauthorized)
		//	encodeJSON(w, map[string]string{"error": "Unauthorized"})
		//	log.Println("ChirpCheck", err)
		//	return
		//}

		chirps := make([]database.Chirp, 0)

		if author_id != uuid.Nil {
			chirps, err = config.db.GetChirpsByUser(r.Context(), author_id)
		} else {
			chirps, err = config.db.GetChirps(r.Context())
		}

		if sortOrder == "desc" {
			sort.Slice(chirps, func(i, j int) bool {
				return chirps[i].CreatedAt.After(chirps[j].CreatedAt)
			})
		}

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			encodeJSON(w, map[string]string{"error": "Internal server error"})
			log.Println(err)
			return
		}

		outChirps := make([]map[string]interface{}, 0)

		for _, chirp := range chirps {
			outChirps = append(outChirps, map[string]interface{}{
				"id":         chirp.ID,
				"created_at": chirp.CreatedAt,
				"updated_at": chirp.UpdatedAt,
				"user_id":    chirp.UserID,
				"body":       chirp.Body,
			})
		}

		w.WriteHeader(http.StatusOK)
		encodeJSON(w, outChirps)
	}
}

func Chirp(config *apiConfig) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		chirpID, err := uuid.Parse(r.PathValue("chirpID"))

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			encodeJSON(w, map[string]string{"error": "Invalid chirp ID"})
			log.Println(err)
			return
		}

		chirp, err := config.db.GetChirp(r.Context(), chirpID)

		if err == sql.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			encodeJSON(w, map[string]string{"error": "Chirp not found"})
			return
		}

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			encodeJSON(w, map[string]string{"error": "Internal server error"})
			log.Println(err)
			return
		}

		outChirp := map[string]interface{}{
			"id":         chirp.ID,
			"created_at": chirp.CreatedAt,
			"updated_at": chirp.UpdatedAt,
			"user_id":    chirp.UserID,
			"body":       chirp.Body,
		}

		w.WriteHeader(http.StatusOK)
		encodeJSON(w, outChirp)
	}

}

type Authing struct {
	Password string `json:"password"`
	Email    string `json:"email"`
}

func UserLogin(config *apiConfig) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var authUser Authing

		body, err := io.ReadAll(r.Body)

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Println(err)

			return
		}

		err = json.Unmarshal(body, &authUser)

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Println(err)

			return
		}

		if len(authUser.Email) == 0 || len(authUser.Password) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			encodeJSON(w, map[string]string{"error": "Email or password is not provided"})

			return
		}

		user, err := config.db.GetUser(r.Context(), authUser.Email)

		if auth.ComparePassword(user.Password, authUser.Password) != nil {
			w.WriteHeader(http.StatusUnauthorized)
			encodeJSON(w, map[string]string{"error": "Unauthorized"})
			return
		}

		token, err := auth.MakeToken(user.ID, config.secret, 0)

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			log.Println(err)

			return
		}

		refresh_token, err := auth.MakeRefreshToken()

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			log.Println(err)

			return
		}

		config.db.AddToken(r.Context(), database.AddTokenParams{
			Token:  refresh_token,
			UserID: user.ID,
		})

		w.WriteHeader(http.StatusOK)
		encodeJSON(w, map[string]interface{}{
			"id":            user.ID,
			"created_at":    user.CreatedAt,
			"updated_at":    user.UpdatedAt,
			"email":         user.Email,
			"is_chirpy_red": user.IsChirpyRed,
			"token":         token,
			"refresh_token": refresh_token,
		})
	}
}

func main() {
	env := godotenv.Load(".env")

	config := &apiConfig{}

	if env != nil {
		config.dbUri = os.Getenv("DB_URL")
		config.platform = os.Getenv("PLATFORM")
		config.secret = os.Getenv("SECRET")
		config.polkaApi = os.Getenv("POLKA_API")
	} else {
		config.dbUri = "postgresql://postgres@localhost:5432/chirpy?sslmode=disable"
		config.platform = "Development"
		config.secret = "SHHH_ITS_A_SECRET"
		config.polkaApi = "f271c81ff7084ee5b99a5091b42d486e"
	}

	db, err := sql.Open("postgres", config.dbUri)

	if err != nil {
		log.Fatal(err)
	}

	config.db = database.New(db)

	serverMux := http.ServeMux{}

	serverMux.HandleFunc("POST /api/users", CreateUser(config))
	serverMux.HandleFunc("POST /api/chirps", ChirpCheck(config))
	serverMux.HandleFunc("POST /api/login", UserLogin(config))
	serverMux.HandleFunc("POST /api/refresh", RefreshToken(config))
	serverMux.HandleFunc("POST /api/revoke", RevokeToken(config))

	// Redness
	serverMux.HandleFunc("POST /api/polka/webhooks", PolkaHook(config))

	serverMux.HandleFunc("PUT /api/users", UpdateUser(config))

	serverMux.HandleFunc("GET /api/healthz", HealthCheck)

	serverMux.HandleFunc("GET /api/chirps/{chirpID}", Chirp(config))
	serverMux.HandleFunc("GET /api/chirps", Chirps(config))

	serverMux.HandleFunc("DELETE /api/chirps/{chirpID}", DeleteChirp(config))

	serverMux.HandleFunc("POST /admin/reset", ResetHits(config))
	serverMux.HandleFunc("GET /admin/metrics", Metrics(config))

	handler := http.StripPrefix("/app", http.FileServer(http.Dir("./public")))

	serverMux.Handle("/app/", AddHit(config, handler))

	server := http.Server{
		Addr:    "localhost:38080",
		Handler: &serverMux,
	}

	log.Fatal(server.ListenAndServe())
}

func DeleteChirp(config *apiConfig) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := auth.GetBearerToken(r.Header)

		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			encodeJSON(w, map[string]string{"error": "Unauthorized"})
			return
		}

		userId, err := auth.ValidateToken(token, config.secret)

		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			encodeJSON(w, map[string]string{"error": "Unauthorized"})
			log.Println("UpdateUser", err)
			return
		}

		chirp, err := config.db.GetChirp(r.Context(), uuid.MustParse(r.PathValue("chirpID")))

		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			encodeJSON(w, map[string]string{"error": "Chirp not found"})
			return
		}

		if userId != chirp.UserID {
			w.WriteHeader(http.StatusForbidden)
			encodeJSON(w, map[string]string{"error": "Forbidden"})
			return
		}

		err = config.db.DeleteChirp(r.Context(), chirp.ID)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			encodeJSON(w, map[string]string{"error": "Internal server error"})
			log.Println(err)
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func UpdateUser(config *apiConfig) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := auth.GetBearerToken(r.Header)

		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			encodeJSON(w, map[string]string{"error": "Unauthorized"})
			return
		}

		userId, err := auth.ValidateToken(token, config.secret)

		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			encodeJSON(w, map[string]string{"error": "Unauthorized"})
			log.Println("UpdateUser", err)
			return
		}

		var inUser newUser

		body, err := io.ReadAll(r.Body)

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Println(err)

			return
		}

		err = json.Unmarshal(body, &inUser)

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Println(err)

			return
		}

		if len(inUser.Email) == 0 || len(inUser.Password) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			encodeJSON(w, map[string]string{"error": "Email or password is not provided"})

			return
		}

		pass, err := auth.HashPassword(inUser.Password)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Println(err)

			return
		}

		user, err := config.db.UpdateUser(r.Context(), database.UpdateUserParams{
			ID:       userId,
			Email:    inUser.Email,
			Password: string(pass),
		})

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Println(err)

			return
		}

		outUser := map[string]interface{}{
			"id":            user.ID,
			"created_at":    user.CreatedAt,
			"updated_at":    user.UpdatedAt,
			"email":         user.Email,
			"is_chirpy_red": user.IsChirpyRed,
		}

		w.WriteHeader(http.StatusOK)
		encodeJSON(w, outUser)
	}
}

func RevokeToken(config *apiConfig) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := auth.GetBearerToken(r.Header)

		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			encodeJSON(w, map[string]string{"error": "Unauthorized"})
			return
		}

		err = config.db.RevokeToken(r.Context(), token)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			encodeJSON(w, map[string]string{"error": "Internal server error"})
			log.Println(err)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func RefreshToken(config *apiConfig) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := auth.GetBearerToken(r.Header)

		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			encodeJSON(w, map[string]string{"error": "Unauthorized"})
			return
		}

		refresh_token, dbErr := config.db.GetToken(r.Context(), token)

		if dbErr != nil {
			w.WriteHeader(http.StatusUnauthorized)
			encodeJSON(w, map[string]string{"error": "Unauthorized"})
			log.Println("RefreshToken", dbErr)
			return
		}

		newToken, err := auth.MakeToken(refresh_token.UserID, config.secret, 0)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			encodeJSON(w, map[string]string{"error": "Internal server error"})
			return
		}

		w.WriteHeader(http.StatusOK)
		encodeJSON(w, map[string]interface{}{
			"token": newToken,
		})
	}
}

type UserEvent struct {
	Event string `json:"event"`
	Data  struct {
		UserId string `json:"user_id"`
	} `json:"data"`
}

func PolkaHook(config *apiConfig) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKey, err := auth.GetAPIKey(r.Header)

		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			encodeJSON(w, map[string]string{"error": "Unauthorized"})
			return
		}

		if apiKey != config.polkaApi {
			w.WriteHeader(http.StatusUnauthorized)
			encodeJSON(w, map[string]string{"error": "Unauthorized"})
		}

		var event UserEvent

		body, err := io.ReadAll(r.Body)

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			log.Println("PolkaHook", err)

			return
		}

		err = json.Unmarshal(body, &event)

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			log.Println("PolkaHook", err)

			return
		}

		if event.Event != "user.upgraded" {
			w.WriteHeader(http.StatusNoContent)

			return
		}

		user, err := config.db.GetUserById(r.Context(), uuid.MustParse(event.Data.UserId))

		if err != nil || user.ID == uuid.Nil {
			w.WriteHeader(http.StatusNotFound)

			log.Println("PolkaHook", err)

			return
		}

		config.db.UpdateIsRed(r.Context(), database.UpdateIsRedParams{
			ID:          user.ID,
			IsChirpyRed: true,
		})

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)

			log.Println("PolkaHook", err)

			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
