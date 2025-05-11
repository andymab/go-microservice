package main

import (
	"myapp/database"
	"myapp/models"
)

func main() {
	database.InitDB()

	// Создание администратора
	admin := models.User{
		Email:    "admin@example.com",
		Password: "admin123", // Будет автоматически хеширован
		Name:     "Admin",
	}

	database.DB.Create(&admin)
}