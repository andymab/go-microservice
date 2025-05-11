# go-microservice

# Документация проекта: Микросервис авторизации на Go с Nginx и HTTPS

## Содержание
 - [Обзор проекта](#обзор-проекта)
 - [Требования к системе](#требования-к-системе)
 - [Установка и настройка](#установка-и-настройка)
 - [Описание файлов проекта](#описание-файлов-проекта)
 - [API Endpoints](#api-endpoints)
 - [Тестирование с помощью curl](#тестирование-с-помощью-curl)
 - [Развертывание с Nginx](#развертывание-с-nginx)
 - [Генерация SSL сертификата](#генерация-ssl-сертификата)
 - [Подробный разбор файлов проекта](#подробный-разбор-файлов-проекта)
    - [go.mod и go.sum](#1-gomod-и-gosum)
    - [database/db.go](#2-databasedbgo)
    - [handlers/auth.go](#3-handlersauthgo)
    - [main.go](#4-maingo)
    - [auth/auth.go](#5-authauthgo)
    - [models/user.go](#6-modelsusergo)
    - [nginx_myapp.conf](#7-nginx_myappconf)
    - [scripts/seed.go](#8-scriptsseedgo)
 - [Полное руководство по настройке окружения для Go-приложения](#полное-руководство-по-настройке-окружения-для-go-приложения)
 - [Настройка PostgreSQL](#1-настройка-postgresql)
    - [Создание базы данных и пользователя](#создание-базы-данных-и-пользователя)
		- [Добавляем строку для доступа](#добавляем-строку-для-доступа)
		- [Перезапускаем PostgreSQL](#перезапускаем-postgresql)
	- [Перезапускаем PostgreSQL](#перезапускаем-postgresql)
 - [Создание самоподписного SSL-сертификата](#2-создание-самоподписного-ssl-сертификата)
 - [Создание systemd-сервиса для автоматического запуска](#3-создание-systemd-сервиса-для-автоматического-запуска)
 - [Настройка логирования через journald:](#настройка-логирования-через-journald)
 - [Полезные команды для управления сервисом:](#полезные-команды-для-управления-сервисом)
 - [Проверка работоспособности системы](#4-проверка-работоспособности-системы)
 - [Дополнительные настройки безопасности](#5-дополнительные-настройки-безопасности)
 - [Рекомендации по улучшению](#рекомендации-по-улучшению)

## Обзор проекта

Проект представляет собой микросервис аутентификации на языке Go, который включает:
- Регистрацию и авторизацию пользователей
- JWT-аутентификацию с access и refresh токенами
- Защищенные маршруты
- Проксирование через Nginx с HTTPS
- Автоматическое хеширование паролей
- Миграции базы данных

## Требования к системе

- Go 1.23+
- PostgreSQL
- Nginx
- OpenSSL (для генерации самоподписанных сертификатов)

## Установка и настройка

### Установка GIT
```bash
sudo apt update && sudo apt install git -y

echo "# go-microservice" >> README.md
git init
git add README.md
git commit -m "first commit"
git branch -M main
git remote add origin https://github.com/andymab/go-microservice.git
git push -u origin main
```

1. **Установка Go**:
   ```bash
   sudo apt update
   sudo apt install golang
   ```

2. **Установка PostgreSQL**:
   ```bash
   sudo apt install postgresql postgresql-contrib
   sudo -u postgres psql -c "CREATE USER goapp_user WITH PASSWORD 'dbtxt472';"
   sudo -u postgres psql -c "CREATE DATABASE goapp_db OWNER goapp_user;"
   ```

3. **Клонирование проекта**:
   ```bash
   git clone <ваш-репозиторий>
   cd <проект>
   go mod download
   ```

4. **Настройка переменных окружения**:
   Создайте файл `.env` в корне проекта:
   ```
   DB_HOST=localhost
   DB_USER=goapp_user
   DB_PASSWORD=dbtxt472
   DB_NAME=goapp_db
   DB_PORT=5432
   JWT_SECRET=your-very-secret-key-at-least-32-chars
   ```

## Описание файлов проекта

### `main.go`
Главный файл приложения, который:
- Инициализирует базу данных и JWT
- Настраивает маршруты:
  - `/api/register` - регистрация пользователя
  - `/api/login` - авторизация
  - `/api/refresh` - обновление токенов
  - `/api/protected` - защищенный маршрут
- Запускает сервер на порту 8080

### `auth/auth.go`
Содержит логику работы с JWT:
- `InitJWT` - инициализация JWT с секретным ключом
- `GenerateTokens` - генерация access (15 мин) и refresh (7 дней) токенов

### `database/db.go`
Настройка подключения к PostgreSQL и автоматические миграции для модели User.

### `handlers/auth.go`
Обработчики HTTP запросов:
- `Register` - регистрация нового пользователя
- `Login` - авторизация и выдача токенов
- `RefreshTokens` - обновление токенов по refresh токену

### `models/user.go`
Модель пользователя с автоматическим хешированием пароля перед сохранением.

### `nginx_myapp.conf`
Конфигурация Nginx:
- Проксирование запросов на Go-сервер
- HTTPS настройки с самоподписанным сертификатом
- Перенаправление HTTP → HTTPS

### `scripts/seed.go`
Скрипт для создания тестового пользователя (admin@example.com).

## API Endpoints

### Регистрация пользователя
```
POST /api/register
Content-Type: application/json

{
    "email": "user@example.com",
    "password": "password123",
    "name": "User Name"
}
```

### Авторизация
```
POST /api/login
Content-Type: application/json

{
    "email": "user@example.com",
    "password": "password123"
}
```

Ответ:
```json
{
    "access_token": "eyJ...",
    "refresh_token": "eyJ..."
}
```

### Обновление токенов
```
POST /api/refresh
Content-Type: application/json

{
    "refresh_token": "eyJ..."
}
```

Ответ аналогичен авторизации.

### Защищенный маршрут
```
GET /api/protected
Authorization: Bearer 
```

## Тестирование с помощью curl

1. Регистрация:
```bash
curl -X POST https://mab-dacha.ru/api/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com", "password":"test123", "name":"Test User"}'
```

2. Авторизация:
```bash
curl -X POST https://mab-dacha.ru/api/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com", "password":"test123"}'
```

3. Доступ к защищенному маршруту:
```bash
curl https://mab-dacha.ru/api/protected \
  -H "Authorization: Bearer "
```

4. Обновление токенов:
```bash
curl -X POST https://mab-dacha.ru/api/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":""}'
```

## Развертывание с Nginx

1. Установите Nginx:
```bash
sudo apt install nginx
```

2. Разместите конфиг `nginx_myapp.conf` в `/etc/nginx/sites-available/`

3. Создайте симлинк:
```bash
sudo ln -s /etc/nginx/sites-available/nginx_myapp.conf /etc/nginx/sites-enabled/
```

4. Проверьте конфигурацию и перезапустите Nginx:
```bash
sudo nginx -t
sudo systemctl restart nginx
```

5. Запустите Go-приложение (можно использовать systemd или screen):
```bash
go run main.go
```

## Генерация SSL сертификата

1. Создайте ключ и сертификат:
```bash
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/private/mab-dacha.ru.key \
  -out /etc/ssl/certs/mab-dacha.ru.crt
```

2. Установите правильные разрешения:
```bash
sudo chmod 600 /etc/ssl/private/mab-dacha.ru.key
```

3. Обновите конфигурацию Nginx и перезапустите его.

---

Эта документация охватывает все аспекты проекта, от установки до тестирования. Для дополнительной безопасности рекомендуется заменить самоподписанный сертификат на сертификат от Let's Encrypt в production среде.


## Подробный разбор файлов проекта

### 1. `go.mod` и `go.sum`
**Назначение**: Файлы зависимостей Go-проекта.

**Содержание `go.mod`**:
```go
module myapp  // Имя модуля

go 1.23.0    // Версия Go
toolchain go1.23.9  // Версия инструментария

// Основные зависимости
require (
    github.com/go-chi/chi/v5 v5.2.1       // Маршрутизатор
    github.com/go-chi/jwtauth/v5 v5.3.3   // JWT-аутентификация
    golang.org/x/crypto v0.38.0           // Криптографические функции
    gorm.io/driver/postgres v1.5.11       // Драйвер PostgreSQL для GORM
    gorm.io/gorm v1.26.1                  // ORM
)

// Косвенные зависимости
require (
    github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // Криптография
    github.com/goccy/go-json v0.10.5      // Альтернативный JSON-парсер
    // ... другие косвенные зависимости
)
```

**Содержание `go.sum`**:  
Содержит точные хеши всех зависимостей для проверки целостности. Формат:
```
<модуль> <версия>/go.mod <хеш>
```

---

### 2. `database/db.go`
**Назначение**: Инициализация подключения к БД и миграции.

**Ключевые части**:
```go
var DB *gorm.DB  // Глобальная переменная подключения

func InitDB() error {
    // Формат DSN для PostgreSQL
    dsn := "host=localhost user=goapp_user password=dbtxt472 dbname=goapp_db port=5432 sslmode=disable"
    
    // Подключение
    DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
    
    // Автомиграция модели User
    DB.AutoMigrate(&models.User{})
}
```

**Параметры подключения**:
- `host`: Адрес сервера БД
- `user`: Имя пользователя
- `password`: Пароль
- `dbname`: Имя базы данных
- `port`: Порт PostgreSQL (по умолчанию 5432)
- `sslmode`: Отключение SSL для разработки

---

### 3. `handlers/auth.go`
**Назначение**: Обработчики HTTP-запросов для аутентификации.

#### `Register`:
```go
func Register(w http.ResponseWriter, r *http.Request) {
    // 1. Декодирование JSON
    var user models.User
    json.NewDecoder(r.Body).Decode(&user)
    
    // 2. Проверка существования пользователя
    database.DB.Where("email = ?", user.Email).First(&existingUser)
    
    // 3. Хеширование пароля (автоматически через BeforeSave)
    // 4. Сохранение пользователя
    database.DB.Create(&user)
}
```

#### `Login`:
```go
func Login(w http.ResponseWriter, r *http.Request) {
    // 1. Проверка учетных данных
    bcrypt.CompareHashAndPassword(
        []byte(user.Password), 
        []byte(credentials.Password)
    )
    
    // 2. Генерация токенов
    auth.GenerateTokens(user.ID)
}
```

#### `RefreshTokens`:
```go
func RefreshTokens(w http.ResponseWriter, r *http.Request) {
    // 1. Верификация токена
    token, err := jwtauth.VerifyToken(auth.TokenAuth, request.RefreshToken)
    
    // 2. Проверка срока действия
    exp := claims["exp"].(float64)
    if time.Now().Unix() > int64(exp) { ... }
    
    // 3. Генерация новых токенов
    auth.GenerateTokens(uint(userID))
}
```

---

### 4. `main.go`
**Назначение**: Точка входа в приложение.

**Структура**:
```go
func main() {
    // 1. Инициализация БД
    database.InitDB()
    
    // 2. Инициализация JWT
    auth.InitJWT("your-very-secret-key-at-least-32-chars")
    
    // 3. Настройка маршрутов
    r := chi.NewRouter()
    r.Use(middleware.Logger)  // Логирование
    
    // 4. Группа публичных маршрутов
    r.Post("/api/register", handlers.Register)
    r.Post("/api/login", handlers.Login)
    
    // 5. Группа защищенных маршрутов
    r.Group(func(r chi.Router) {
        r.Use(jwtauth.Verifier(auth.TokenAuth))
        r.Use(jwtauth.Authenticator)
        r.Get("/api/protected", ...)
    })
}
```

---

### 5. `auth/auth.go`
**Назначение**: Работа с JWT-токенами.

**Ключевые функции**:
```go
// Инициализация JWT
func InitJWT(secret string) {
    TokenAuth = jwtauth.New("HS256", []byte(secret), nil)
}

// Генерация токенов
func GenerateTokens(userID uint) (string, string, error) {
    // Access token (15 минут)
    _, accessToken, _ := TokenAuth.Encode(map[string]interface{}{
        "user_id": userID,
        "exp": time.Now().Add(15 * time.Minute).Unix(),
    })
    
    // Refresh token (7 дней)
    _, refreshToken, _ := TokenAuth.Encode(map[string]interface{}{
        "user_id": userID,
        "exp": time.Now().Add(7 * 24 * time.Hour).Unix(),
    })
}
```

---

### 6. `models/user.go`
**Назначение**: Модель пользователя и бизнес-логика.

**Структура**:
```go
type User struct {
    gorm.Model           // Встроенная модель (ID, CreatedAt и т.д.)
    Email    string `gorm:"unique;not null"`
    Password string `gorm:"not null"`
    Name     string
}

// Хук BeforeSave - автоматическое хеширование пароля
func (u *User) BeforeSave(tx *gorm.DB) error {
    hashedPassword, err := bcrypt.GenerateFromPassword(
        []byte(u.Password), 
        bcrypt.DefaultCost
    )
    u.Password = string(hashedPassword)
    return err
}
```

---

### 7. `nginx_myapp.conf`
**Назначение**: Конфигурация Nginx для проксирования и HTTPS.

**Ключевые секции**:
```nginx
server {
    listen 443 ssl;
    server_name mab-dacha.ru;
    
    # SSL сертификаты
    ssl_certificate /etc/ssl/certs/mab-dacha.ru.crt;
    ssl_certificate_key /etc/ssl/private/mab-dacha.ru.key;
    
    # Проксирование API
    location /api/ {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
    
    # Статические файлы
    location /static/ {
        alias /var/www/mab-dacha.ru/static/;
        expires 30d;
    }
}

# Перенаправление HTTP → HTTPS
server {
    listen 80;
    return 301 https://$host$request_uri;
}
```

---

### 8. `scripts/seed.go`
**Назначение**: Наполнение БД тестовыми данными.

**Содержание**:
```go
func main() {
    database.InitDB()
    
    admin := models.User{
        Email:    "admin@example.com",
        Password: "admin123", // Автоматически хешируется
        Name:     "Admin",
    }
    
    database.DB.Create(&admin)
}
```

---

## Особенности реализации

1. **Безопасность**:
   - Пароли хешируются с bcrypt перед сохранением
   - JWT-токены подписываются с использованием HS256
   - Refresh токены имеют ограниченный срок действия

2. **Архитектура**:
   - Четкое разделение на слои (handlers, models, database)
   - Использование dependency injection (передача DB и JWT)

3. **Масштабируемость**:
   - Подготовка к кластеризации через Nginx
   - Возможность добавления новых моделей через миграции

4. **Логирование**:
   - Встроенное логирование в critical path (аутентификация)
   - Middleware для логирования запросов

Этот разбор показывает, как каждый компонент системы взаимодействует с другими, обеспечивая надежную систему аутентификации.



## Полное руководство по настройке окружения для Go-приложения

### 1. Настройка PostgreSQL

#### Создание базы данных и пользователя:
```bash
sudo -u postgres psql  # Вход в консоль PostgreSQL

-- В консоли PostgreSQL выполняем:
CREATE DATABASE goapp_db;
CREATE USER goapp_user WITH PASSWORD 'dbtxt472';
GRANT ALL PRIVILEGES ON DATABASE goapp_db TO goapp_user;
ALTER DATABASE goapp_db OWNER TO goapp_user;

-- Настройка доступа (редактируем pg_hba.conf)
sudo nano /etc/postgresql/<версия>/main/pg_hba.conf
```

#### Добавляем строку для доступа:
```
# TYPE  DATABASE   USER        ADDRESS     METHOD
host    goapp_db   goapp_user  127.0.0.1   md5
```

#### Перезапускаем PostgreSQL:
```bash
sudo systemctl restart postgresql
```

### 2. Создание самоподписного SSL-сертификата

#### Генерация сертификата:
```bash
sudo mkdir -p /etc/ssl/{certs,private}
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/mab-dacha.ru.key \
    -out /etc/ssl/certs/mab-dacha.ru.crt \
    -subj "/C=RU/ST=Moscow/L=Moscow/O=MyCompany/CN=mab-dacha.ru"
```

#### Установка прав:
```bash
sudo chmod 600 /etc/ssl/private/mab-dacha.ru.key
sudo chmod 644 /etc/ssl/certs/mab-dacha.ru.crt
```

#### Проверка сертификата:
```bash
openssl x509 -in /etc/ssl/certs/mab-dacha.ru.crt -noout -text
```

### 3. Создание systemd-сервиса для автоматического запуска

#### Создаем файл сервиса:
```bash
sudo nano /etc/systemd/system/myapp.service
```

#### Содержимое файла сервиса:
```ini
[Unit]
Description=My Go Application
After=network.target postgresql.service

[Service]
Type=simple
User=ubuntu
Group=ubuntu
WorkingDirectory=/home/ubuntu/myapp
ExecStart=/usr/local/go/bin/go run /home/ubuntu/myapp/main.go
Restart=always
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=myapp
Environment=GIN_MODE=release
EnvironmentFile=/home/ubuntu/myapp/.env

[Install]
WantedBy=multi-user.target
```

#### Настройка логирования через journald:
```bash
sudo nano /etc/rsyslog.d/myapp.conf
```
Добавляем:
```
if $programname == 'myapp' then /var/log/myapp.log
& stop
```

#### Применяем изменения:
```bash
sudo systemctl daemon-reload
sudo systemctl enable myapp.service
sudo systemctl start myapp.service
```

#### Полезные команды для управления сервисом:
```bash
# Проверка статуса
sudo systemctl status myapp

# Просмотр логов
journalctl -u myapp -f

# Перезапуск сервиса
sudo systemctl restart myapp

# Включение автозапуска
sudo systemctl enable myapp
```

### 4. Проверка работоспособности системы

#### Проверка подключения к БД:
```bash
psql -h 127.0.0.1 -U goapp_user -d goapp_db -W
```

#### Проверка сетевых соединений:
```bash
ss -tulnp | grep 8080  # Проверка работы Go-приложения
sudo nginx -t          # Проверка конфигурации Nginx
```

#### Проверка HTTPS:
```bash
curl -vk https://mab-dacha.ru/api/
```

### 5. Дополнительные настройки безопасности

#### Настройка firewall:
```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

#### Рекомендации по улучшению:
1. Заменить самоподписанный сертификат на Let's Encrypt
2. Настроить регулярное резервное копирование БД
3. Реализовать ротацию логов
4. Настроить мониторинг ресурсов

Эта конфигурация обеспечит:
- Автоматический запуск приложения при загрузке системы
- Централизованное логирование через systemd
- Безопасное HTTPS-соединение
- Изолированный доступ к базе данных
- Удобное управление сервисом через systemctl