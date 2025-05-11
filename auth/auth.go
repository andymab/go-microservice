package auth

import (
	"github.com/go-chi/jwtauth/v5"
	"time"
	"log"
	"fmt"
)

var TokenAuth *jwtauth.JWTAuth

func InitJWT(secret string) {
	TokenAuth = jwtauth.New("HS256", []byte(secret), nil)
}

func GenerateTokens(userID uint) (string, string, error) {
    now := time.Now()
    accessExp := now.Add(15 * time.Minute).Unix()
    refreshExp := now.Add(7 * 24 * time.Hour).Unix()

    // Логируем параметры перед генерацией
    log.Printf("Generating tokens for user %d. Access exp: %d, Refresh exp: %d", 
        userID, accessExp, refreshExp)

    // Access token
    _, accessToken, err := TokenAuth.Encode(map[string]interface{}{
        "user_id": userID,
        "exp":     accessExp,
    })
    if err != nil {
        return "", "", fmt.Errorf("access token generation failed: %w", err)
    }

    // Refresh token
    _, refreshToken, err := TokenAuth.Encode(map[string]interface{}{
        "user_id": userID,
        "exp":     refreshExp,
    })
    if err != nil {
        return "", "", fmt.Errorf("refresh token generation failed: %w", err)
    }

    // Декодируем для проверки
    if _, err := jwtauth.VerifyToken(TokenAuth, refreshToken); err != nil {
        return "", "", fmt.Errorf("generated refresh token verification failed: %w", err)
    }

    return accessToken, refreshToken, nil
}