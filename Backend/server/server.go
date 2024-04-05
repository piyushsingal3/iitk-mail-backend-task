package server

import (
	"log"
	"serve/handler"
	"serve/middleware"
	"serve/store"

	"github.com/gin-contrib/cors"

	"github.com/gin-gonic/gin"
)

func Performserver(m *store.MongoStore) {
	router := gin.Default()
	router.Use(cors.Default())

	router.POST("/users/signup", func(c *gin.Context) {
		handler.SignUp(c, m)

	})
	router.GET("/login/receivedMails/:email/:password", func(c *gin.Context) {
		handler.LoginRecievedMails(c, m)

	})
	router.GET("/filterReceivedMailsOnSender/:email/:password/:senderemail", func(c *gin.Context) {
		handler.FilterRecievedMailsOnSender(c, m)

	})
	router.GET("/filterReceivedMailsOnSubject/:email/:password/:subject", func(c *gin.Context) {
		handler.FilterRecievedMailsOnSubject(c, m)

	})
	router.POST("/users/login", func(c *gin.Context) {
		handler.Login(c, m)

	})
	router.GET("/get/:email", func(c *gin.Context) {
		handler.GetUsersByEmails(c, m)
	})
	router.GET("/login/sentMails/:email/:password", func(c *gin.Context) {
		handler.LoginSentMails(c, m)

	})
	router.GET("/filterSentMailsOnSubject/:email/:password/:subject", func(c *gin.Context) {
		handler.FilterSentMailsOnSubject(c, m)

	})
	router.GET("/filterSentMailsOnRecipient/:email/:password/:recipientemail", func(c *gin.Context) {
		handler.FilterSentMailsOnRecipient(c, m)

	})
	router.Use(middleware.Authentication())
	router.GET("/api-1", func(c *gin.Context) {

		c.JSON(200, gin.H{"success": "Access granted for api-1"})

	})
	router.POST("/composemail", func(c *gin.Context) {
		handler.ComposeMail(c, m)
	})
	if err := m.OpenConnectionWithMongoDB("mongodb://localhost:27017", "iitk-mail"); err != nil {
		log.Fatalf("Failed to open connection with MongoDB: %v", err)
	}

	//runs the server with localhost
	if err := router.Run(":9000"); err != nil {
		log.Fatalf("Failed to run the server: %v", err)

	}
}
