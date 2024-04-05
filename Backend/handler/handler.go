package handler

import (
	"context"

	"fmt"
	"log"

	"net/http"
	"serve/helper"
	"serve/models"
	"serve/store"
	"time"

	"github.com/go-playground/validator/v10"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

var validate = validator.New()

func ComposeMail(c *gin.Context, m *store.MongoStore) {
	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

	var maildata models.Mails

	if err := c.BindJSON(&maildata); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		fmt.Println(err)
		return
	}

	validationErr := validate.Struct(maildata)
	if validationErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": validationErr.Error()})
		fmt.Println(validationErr)
		return
	}

	result, insertErr := m.EmailCollection.InsertOne(ctx, maildata)
	if insertErr != nil {
		msg := fmt.Sprintf("mail not composed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
		fmt.Println(insertErr)
		return
	}
	defer cancel()

	c.JSON(http.StatusOK, result)
}

func HashPassword(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Panic(err)

	}

	return string(bytes)
}
func SignUp(c *gin.Context, m *store.MongoStore) {
	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
	var user models.User

	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	validationErr := validate.Struct(user)
	if validationErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": validationErr.Error()})
		return
	}

	count, err := m.UsersCollection.CountDocuments(ctx, bson.M{"email": user.Email})
	defer cancel()
	if err != nil {
		log.Panic(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while checking for the email"})
		return
	}

	password := HashPassword(*user.Password)
	user.Password = &password

	if count > 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "this email already exists"})
		return

	}

	user.CreatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	user.UpdatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	user.ID = primitive.NewObjectID()

	token, refreshToken, _ := helper.GenerateAllTokens(user.Email, user.UserID)
	user.Token = &token
	user.Refresh_token = &refreshToken

	resultInsertionNumber, insertErr := m.UsersCollection.InsertOne(ctx, user)
	if insertErr != nil {
		msg := fmt.Sprintf("User item was not created")
		c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
		return
	}
	defer cancel()

	c.JSON(http.StatusOK, resultInsertionNumber)

}

func VerifyPassword(userPassword string, providedPassword string) (bool, string) {
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	check := true
	msg := ""

	if err != nil {
		msg = fmt.Sprintf("login or passowrd is incorrect")
		check = false
	}

	return check, msg
}

func GetUsersByEmails(c *gin.Context, m *store.MongoStore) {

	email := c.Params.ByName("email")

	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

	var users []models.User

	cursor, err := m.UsersCollection.Find(ctx, bson.M{"email": email})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		fmt.Println(err)
		return
	}

	if err = cursor.All(ctx, &users); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		fmt.Println(err)
		return
	}

	defer cancel()

	c.JSON(http.StatusOK, users)
}
func Login(c *gin.Context, m *store.MongoStore) {

	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
	var user models.User
	var foundUser models.User

	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := m.UsersCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)
	defer cancel()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "login or passowrd is incorrect"})
		return
	}

	passwordIsValid, msg := VerifyPassword(*user.Password, *foundUser.Password)
	defer cancel()
	if passwordIsValid != true {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
		return
	}

	token, refreshToken, _ := helper.GenerateAllTokens(foundUser.Email, foundUser.UserID)

	helper.UpdateAllTokens(token, refreshToken, foundUser.UserID, m)
	err = m.UsersCollection.FindOne(ctx, bson.M{"user_id": foundUser.UserID}).Decode(&foundUser)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, foundUser)

}
func FilterRecievedMailsOnSender(c *gin.Context, m *store.MongoStore) {

	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
	email := c.Params.ByName("email")
	password := c.Params.ByName("password")
	senderemail := c.Params.ByName("senderemail")
	var foundUser models.User

	err := m.UsersCollection.FindOne(ctx, bson.M{"email": email}).Decode(&foundUser)
	defer cancel()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "login or passowrd is incorrect"})
		return
	}

	passwordIsValid, msg := VerifyPassword(password, *foundUser.Password)
	defer cancel()
	if passwordIsValid != true {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
		return
	}

	token, refreshToken, _ := helper.GenerateAllTokens(foundUser.Email, foundUser.UserID)

	helper.UpdateAllTokens(token, refreshToken, foundUser.UserID, m)

	var foundEmails []models.Mails
	cursor, err := m.EmailCollection.Find(ctx, bson.M{"recipientemail": foundUser.Email, "senderemail": senderemail})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error finding documents: " + err.Error()})
		return
	}
	defer cursor.Close(ctx)
	for cursor.Next(context.Background()) {
		var foundEmail models.Mails
		if err := cursor.Decode(&foundEmail); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error finding documents: " + err.Error()})
			return
		}
		foundEmails = append(foundEmails, foundEmail)
	}
	if err := cursor.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error finding documents: " + err.Error()})
		return
	}
	if err := cursor.All(ctx, &foundEmails); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error decoding results: " + err.Error()})
		return
	}

	if len(foundEmails) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "no mails found"})
		return
	}

	c.JSON(http.StatusOK, foundEmails)

}
func FilterRecievedMailsOnSubject(c *gin.Context, m *store.MongoStore) {

	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
	email := c.Params.ByName("email")
	password := c.Params.ByName("password")
	subject := c.Params.ByName("subject")
	var foundUser models.User

	err := m.UsersCollection.FindOne(ctx, bson.M{"email": email}).Decode(&foundUser)
	defer cancel()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "login or passowrd is incorrect"})
		return
	}

	passwordIsValid, msg := VerifyPassword(password, *foundUser.Password)
	defer cancel()
	if passwordIsValid != true {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
		return
	}

	token, refreshToken, _ := helper.GenerateAllTokens(foundUser.Email, foundUser.UserID)

	helper.UpdateAllTokens(token, refreshToken, foundUser.UserID, m)

	var foundEmails []models.Mails
	cursor, err := m.EmailCollection.Find(ctx, bson.M{"recipientemail": foundUser.Email, "subject": subject})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error finding documents: " + err.Error()})
		return
	}
	defer cursor.Close(ctx)
	for cursor.Next(context.Background()) {
		var foundEmail models.Mails
		if err := cursor.Decode(&foundEmail); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error finding documents: " + err.Error()})
			return
		}
		foundEmails = append(foundEmails, foundEmail)
	}
	if err := cursor.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error finding documents: " + err.Error()})
		return
	}
	if err := cursor.All(ctx, &foundEmails); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error decoding results: " + err.Error()})
		return
	}

	if len(foundEmails) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "no mails found"})
		return
	}

	c.JSON(http.StatusOK, foundEmails)

}
func LoginRecievedMails(c *gin.Context, m *store.MongoStore) {

	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
	email := c.Params.ByName("email")
	password := c.Params.ByName("password")
	var foundUser models.User

	err := m.UsersCollection.FindOne(ctx, bson.M{"email": email}).Decode(&foundUser)
	defer cancel()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "login or passowrd is incorrect"})
		return
	}

	passwordIsValid, msg := VerifyPassword(password, *foundUser.Password)
	defer cancel()
	if passwordIsValid != true {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
		return
	}

	token, refreshToken, _ := helper.GenerateAllTokens(foundUser.Email, foundUser.UserID)

	helper.UpdateAllTokens(token, refreshToken, foundUser.UserID, m)

	var foundEmails []models.Mails
	cursor, err := m.EmailCollection.Find(ctx, bson.M{"recipientemail": foundUser.Email})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error finding documents: " + err.Error()})
		return
	}
	defer cursor.Close(ctx)
	for cursor.Next(context.Background()) {
		var foundEmail models.Mails
		if err := cursor.Decode(&foundEmail); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error finding documents: " + err.Error()})
			return
		}
		foundEmails = append(foundEmails, foundEmail)
	}
	if err := cursor.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error finding documents: " + err.Error()})
		return
	}
	if err := cursor.All(ctx, &foundEmails); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error decoding results: " + err.Error()})
		return
	}

	if len(foundEmails) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "no mails found"})
		return
	}

	c.JSON(http.StatusOK, foundEmails)

}
func LoginSentMails(c *gin.Context, m *store.MongoStore) {

	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
	email := c.Params.ByName("email")
	password := c.Params.ByName("password")
	var foundUser models.User

	err := m.UsersCollection.FindOne(ctx, bson.M{"email": email}).Decode(&foundUser)
	defer cancel()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "login or passowrd is incorrect"})
		return
	}

	passwordIsValid, msg := VerifyPassword(password, *foundUser.Password)
	defer cancel()
	if passwordIsValid != true {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
		return
	}

	token, refreshToken, _ := helper.GenerateAllTokens(foundUser.Email, foundUser.UserID)

	helper.UpdateAllTokens(token, refreshToken, foundUser.UserID, m)

	var foundEmails []models.Mails
	cursor, err := m.EmailCollection.Find(ctx, bson.M{"senderemail": foundUser.Email})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error finding documents: " + err.Error()})
		return
	}
	defer cursor.Close(ctx)
	for cursor.Next(context.Background()) {
		var foundEmail models.Mails
		if err := cursor.Decode(&foundEmail); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error finding documents: " + err.Error()})
			return
		}
		foundEmails = append(foundEmails, foundEmail)
	}
	if err := cursor.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error finding documents: " + err.Error()})
		return
	}
	if err := cursor.All(ctx, &foundEmails); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error decoding results: " + err.Error()})
		return
	}

	if len(foundEmails) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "no mails found"})
		return
	}

	c.JSON(http.StatusOK, foundEmails)

}
func FilterSentMailsOnSubject(c *gin.Context, m *store.MongoStore) {

	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
	email := c.Params.ByName("email")
	password := c.Params.ByName("password")
	subject := c.Params.ByName("subject")
	var foundUser models.User

	err := m.UsersCollection.FindOne(ctx, bson.M{"email": email}).Decode(&foundUser)
	defer cancel()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "login or passowrd is incorrect"})
		return
	}

	passwordIsValid, msg := VerifyPassword(password, *foundUser.Password)
	defer cancel()
	if passwordIsValid != true {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
		return
	}

	token, refreshToken, _ := helper.GenerateAllTokens(foundUser.Email, foundUser.UserID)

	helper.UpdateAllTokens(token, refreshToken, foundUser.UserID, m)

	var foundEmails []models.Mails
	cursor, err := m.EmailCollection.Find(ctx, bson.M{"senderemail": foundUser.Email, "subject": subject})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error finding documents: " + err.Error()})
		return
	}
	defer cursor.Close(ctx)
	for cursor.Next(context.Background()) {
		var foundEmail models.Mails
		if err := cursor.Decode(&foundEmail); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error finding documents: " + err.Error()})
			return
		}
		foundEmails = append(foundEmails, foundEmail)
	}
	if err := cursor.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error finding documents: " + err.Error()})
		return
	}
	if err := cursor.All(ctx, &foundEmails); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error decoding results: " + err.Error()})
		return
	}

	if len(foundEmails) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "no mails found"})
		return
	}

	c.JSON(http.StatusOK, foundEmails)

}
func FilterSentMailsOnRecipient(c *gin.Context, m *store.MongoStore) {

	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
	email := c.Params.ByName("email")
	password := c.Params.ByName("password")
	recipientemail := c.Params.ByName("recipientemail")
	var foundUser models.User

	err := m.UsersCollection.FindOne(ctx, bson.M{"email": email}).Decode(&foundUser)
	defer cancel()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "login or passowrd is incorrect"})
		return
	}

	passwordIsValid, msg := VerifyPassword(password, *foundUser.Password)
	defer cancel()
	if passwordIsValid != true {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
		return
	}

	token, refreshToken, _ := helper.GenerateAllTokens(foundUser.Email, foundUser.UserID)

	helper.UpdateAllTokens(token, refreshToken, foundUser.UserID, m)

	var foundEmails []models.Mails
	cursor, err := m.EmailCollection.Find(ctx, bson.M{"senderemail": foundUser.Email, "recipientemail": recipientemail})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error finding documents: " + err.Error()})
		return
	}
	defer cursor.Close(ctx)
	for cursor.Next(context.Background()) {
		var foundEmail models.Mails
		if err := cursor.Decode(&foundEmail); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error finding documents: " + err.Error()})
			return
		}
		foundEmails = append(foundEmails, foundEmail)
	}
	if err := cursor.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error finding documents: " + err.Error()})
		return
	}
	if err := cursor.All(ctx, &foundEmails); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error decoding results: " + err.Error()})
		return
	}

	if len(foundEmails) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "no mails found"})
		return
	}

	c.JSON(http.StatusOK, foundEmails)

}
