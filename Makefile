dev: 
	docker-compose up -d

dev-down:
	docker-compose down

start-server:
	air

install-modules:
	go get github.com/go-playground/validator/v10
	go get -u github.com/gofiber/fiber/v2
	go get -u github.com/golang-jwt/jwt/v4
	go get github.com/redis/go-redis/v9
	go get github.com/satori/go.uuid
	go get github.com/spf13/viper
	go get gorm.io/driver/postgres
	go get -u gorm.io/gorm