package main

import (
	"database/sql"
	"log"
	"net/http"
	"regexp"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	db, err := sql.Open("mysql", "root:password@tcp(localhost:3306)/go_gpt")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}

	router := gin.Default()

	router.POST("/register", Register(db))
	router.POST("/login", Login(db))

	err = router.Run(":8080")
	if err != nil {
		log.Fatal(err)
	}
}

func Register(db *sql.DB) func(c *gin.Context) {

	return func(c *gin.Context) {
		var user struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		err := c.BindJSON(&user)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		usernamePattern := regexp.MustCompile("^[A-Za-z0-9!@#$%^&*()_+-=,./?;:'\"{[}\\]]{6,}$")
		if !usernamePattern.MatchString(user.Username) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid username. Must be at least 6 characters long and contain at least one uppercase letter and one special character (!, @, #, $, &, *)"})
			return
		}

		usernameScore := 0
		if len(user.Username) >= 6 {
			usernameScore++
		}
		if regexp.MustCompile("[A-Z]").MatchString(user.Username) {
			usernameScore++
		}
		if regexp.MustCompile("[a-z]").MatchString(user.Username) {
			usernameScore++
		}
		if regexp.MustCompile("[0-9]").MatchString(user.Username) {
			usernameScore++
		}
		if regexp.MustCompile(`[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]`).MatchString(user.Username) {
			usernameScore++
		}

		var count int
		err = db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", user.Username).Scan(&count)
		if err != nil {
			log.Println(err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}
		if count > 0 {
			c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": "Username already exists"})
			return
		}
		if count == 0 {
			usernameScore++
		}

		passwordPattern := regexp.MustCompile("^[A-Za-z0-9!@#$%^&*()_+-=,./?;:'\"{[}\\]]{8,}$")
		if !passwordPattern.MatchString(user.Password) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid password. Must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character (@, $, !, %, *, ?, &, or _) "})
			return
		}

		passwordScore := 0
		if len(user.Password) >= 8 {
			passwordScore++
		}
		if regexp.MustCompile("[A-Z]").MatchString(user.Password) {
			passwordScore++
		}
		if regexp.MustCompile("[a-z]").MatchString(user.Password) {
			passwordScore++
		}
		if regexp.MustCompile("[0-9]").MatchString(user.Password) {
			passwordScore++
		}
		if regexp.MustCompile(`[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]`).MatchString(user.Password) {
			passwordScore++
		}

		if passwordScore < 3 {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Password is too weak. Must have a minimum of 3 out of 5 characteristics: at least 8 characters, at least one uppercase letter, at least one lowercase letter, at least one digit, and at least one special character"})
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			log.Println(err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		result, err := db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", user.Username, string(hashedPassword))
		if err != nil {
			log.Println(err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		id, err := result.LastInsertId()
		if err != nil {
			log.Println(err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message":        "Register Success",
			"id":             id,
			"user":           user.Username,
			"password":       user.Password,
			"Score username": usernameScore,
			"Score password": passwordScore})
	}
}

func Login(db *sql.DB) func(c *gin.Context) {
	return func(c *gin.Context) {
		var user struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		err := c.BindJSON(&user)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		var storedUser struct {
			ID       int    `json:"id"`
			Username string `json:"username"`
			Password string `json:"password"`
		}
		err = db.QueryRow("SELECT id, username, password FROM users WHERE username=?", user.Username).Scan(&storedUser.ID, &storedUser.Username, &storedUser.Password)
		if err != nil {
			log.Println(err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Incorrect username"})
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(user.Password)); err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Incorrect username or password"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Login Success!", "id": storedUser.ID, "user": storedUser.Username})
	}
}
