package main

import (
	"fmt"
	"log"
	"net/http"
	"myapp/auth"
	"myapp/database"
	"myapp/handlers"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/jwtauth/v5"
)

func main() {
    // log.SetFlags(log.LstdFlags | log.Lshortfile) // Добавляет время и файл:строку
    // log.Println("Starting server...")

	// Инициализация базы данных
	if err := database.InitDB(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Инициализация JWT
	auth.InitJWT("your-very-secret-key-at-least-32-chars")

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// API маршруты
	r.Route("/api", func(r chi.Router) {
		r.Post("/register", handlers.Register)
		r.Post("/login", handlers.Login)
		r.Post("/refresh", handlers.RefreshTokens)
		// r.Post("/logout", handlers.Logout)

		// Защищенные маршруты
		r.Group(func(r chi.Router) {
			// Сначала Verifier, затем Authenticator
			r.Use(jwtauth.Verifier(auth.TokenAuth))
			r.Use(jwtauth.Authenticator(auth.TokenAuth)) // Теперь передаем TokenAuth
			
			r.Get("/protected", func(w http.ResponseWriter, r *http.Request) {
				_, claims, _ := jwtauth.FromContext(r.Context())
				userID := claims["user_id"].(float64)
				w.Write([]byte(fmt.Sprintf("Protected area. User ID: %v", userID)))
			})
		})
	})

    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Главная страница"))
    })

	log.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}