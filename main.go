package main

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
)

func main() {
	db, err := sql.Open("mysql", "<user>:<password>@tcp(<host>:<port>)/<database>")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	router := gin.Default()

	router.GET("/users", func(c *gin.Context) {

		rows, err := db.Query("SELECT * FROM users")
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		defer rows.Close()

		var users []map[string]interface{}
		for rows.Next() {
			var id int
			var email, name string
			var power int
			err = rows.Scan(&id, &email, &name, &power)
			if err != nil {
				c.AbortWithError(http.StatusInternalServerError, err)
				return
			}
			user := map[string]interface{}{
				"id":    id,
				"email": email,
				"name":  name,
				"power": power,
			}
			users = append(users, user)
		}

		c.JSON(http.StatusOK, gin.H{"users": users})
	})

	router.Run(":8080")
}
