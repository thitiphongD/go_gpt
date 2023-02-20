package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Password string `json:"password"`
	Power    int    `json:"power"`
}

type RegisterInput struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
	Name     string `json:"name" binding:"required"`
	Power    int    `json:"power"`
}

type TokenClaims struct {
	Email string `json:"email"`
	jwt.StandardClaims
}

func generateToken(email string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)

	claims := &TokenClaims{
		Email: email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	tokenString, err := token.SignedString([]byte("your-secret-key"))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func main() {
	db, err := sql.Open("mysql", "root:password@tcp(localhost:3306)/go_gpt")
	if err != nil {
		panic(err.Error())
	}
	defer db.Close()

	router := gin.Default()

	router.GET("/users", func(ctx *gin.Context) {
		rows, err := db.Query("SELECT * FROM users")
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		var users []User
		for rows.Next() {
			var u User
			err := rows.Scan(&u.ID, &u.Email, &u.Name, &u.Password, &u.Power)
			if err != nil {
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			users = append(users, u)
		}

		ctx.JSON(http.StatusOK, gin.H{"users": users})
	})

	router.POST("/register", func(ctx *gin.Context) {
		var input RegisterInput

		if err := ctx.ShouldBindJSON(&input); err != nil {
			fmt.Println(input)
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var u User
		err := db.QueryRow("SELECT * FROM users WHERE email = ?",
			input.Email).Scan(&u.ID, &u.Email, &u.Name, &u.Password, &u.Power)
		if err == nil {
			ctx.JSON(http.StatusConflict, gin.H{"error": "User with this email already exists"})
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		result, err := db.Exec("INSERT INTO users (email, password, name, power) VALUES (?, ?, ?, ?)",
			input.Email, hashedPassword, input.Name, input.Power)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		id, err := result.LastInsertId()
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		token, err := generateToken(input.Email)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		ctx.JSON(http.StatusOK, gin.H{
			"message": "Registration successful", "id": id, "Email": input.Email, "token": token})

	})

	router.POST("/login", func(ctx *gin.Context) {
		var credentials struct {
			Email    string `json:"email" binding:"required"`
			Password string `json:"password" binding:"required"`
		}
		if err := ctx.ShouldBindJSON(&credentials); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var u User
		err := db.QueryRow("SELECT * FROM users WHERE email = ?", credentials.Email).Scan(&u.ID, &u.Email, &u.Name, &u.Password, &u.Power)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(credentials.Password))
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
			return
		}

		ctx.JSON(http.StatusOK, gin.H{
			"message": "Login success",
			"ID":      u.Email})
	})

	err = router.Run(":8080")
	if err != nil {
		panic(err.Error())
	}
}
