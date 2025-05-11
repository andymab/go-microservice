package handlers

import (
	"encoding/json"
	"log"
	"strings"
	"net/http"
	"time"	

	"myapp/auth"
	"myapp/database"
	"myapp/models"

	"github.com/go-chi/jwtauth/v5"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	

)

// Register - обработчик регистрации пользователя
func Register(w http.ResponseWriter, r *http.Request) {
	var user models.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		// log.Printf("Register JSON decode error: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user.Email = strings.TrimSpace(user.Email)
	user.Password = strings.TrimSpace(user.Password)

	// Проверка существования пользователя
	var existingUser models.User
	if err := database.DB.Where("email = ?", user.Email).First(&existingUser).Error; err == nil {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	// Сохранение пользователя
	if err := database.DB.Create(&user).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}

// Login - обработчик авторизации пользователя
func Login(w http.ResponseWriter, r *http.Request) {
	var credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	credentials.Email = strings.TrimSpace(credentials.Email)
    credentials.Password = strings.TrimSpace(credentials.Password)


	var user models.User
	if err := database.DB.Where("email = ?", credentials.Email).First(&user).Error; err != nil {
		log.Printf("Login failed - user not found: %s. Error: %v", credentials.Email, err)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	// Проверка пароля
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password)); err != nil {
		log.Printf("Password mismatch for %s." , credentials.Email)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Генерация токенов
	accessToken, refreshToken, err := auth.GenerateTokens(user.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func RefreshTokens(w http.ResponseWriter, r *http.Request) {
	var request struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		log.Printf("Refresh tokens decode error: %v", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Верифицируем токен
	token, err := jwtauth.VerifyToken(auth.TokenAuth, request.RefreshToken)
	if err != nil {
		log.Printf("Token verification failed: %v", err)
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	// Получаем claims
	claims := token.PrivateClaims()
	log.Printf("Token claims: %+v", claims)

	// Парсим токен для получения стандартных claims
	parser := new(jwt.Parser)
	parsedToken, _, err := parser.ParseUnverified(request.RefreshToken, jwt.MapClaims{})
	if err != nil {
		log.Printf("Token parse error: %v", err)
		http.Error(w, "Invalid token format", http.StatusUnauthorized)
		return
	}

	// Получаем стандартные claims
	if standardClaims, ok := parsedToken.Claims.(jwt.MapClaims); ok {
		// Проверяем срок действия
		expClaim, ok := standardClaims["exp"]
		if !ok {
			log.Printf("No exp claim in token")
			http.Error(w, "Invalid token format", http.StatusUnauthorized)
			return
		}

		exp, ok := expClaim.(float64)
		if !ok {
			log.Printf("Invalid exp format: %T", expClaim)
			http.Error(w, "Invalid expiration format", http.StatusUnauthorized)
			return
		}

		if time.Now().Unix() > int64(exp) {
			log.Printf("Refresh token expired at %v", time.Unix(int64(exp), 0))
			http.Error(w, "Refresh token expired", http.StatusUnauthorized)
			return
		}

		// Объединяем claims
		for k, v := range standardClaims {
			if _, exists := claims[k]; !exists {
				claims[k] = v
			}
		}
	}

	userID, ok := claims["user_id"].(float64)
	if !ok {
		log.Printf("Invalid user_id in refresh token")
		http.Error(w, "Invalid user ID in token", http.StatusUnauthorized)
		return
	}

	// Генерация новых токенов
	accessToken, refreshToken, err := auth.GenerateTokens(uint(userID))
	if err != nil {
		log.Printf("Token generation error: %v", err)
		http.Error(w, "Failed to generate tokens", http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}