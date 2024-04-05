I have made the backend task for a mail site in golang gin and mongodb. I have explained all the files below-:

1. In models.go i have defined two structures User and Mails. User is the datatype of users that signup and login . Mail is the datatype of emails send or received
2. store.go contains mongoDB structure that contains User and Email collection . store.go also contains function that opens my connection with mongoDB
3. helper.go generate,update and validate the token received when we login
4. middleware.go autthenticates and validates the user
5. server.go file contains various routes of login signup,filtering and composing mail. routes after the authentication middleware can be generated only with token put in the header during POST reques
6. handler.go file contains the handler function of various routes of server and it also hashes the password and then save it
7. main.go runs the server in a goroutine

Now I will explain how to run and use my backend
first run command 'go run main.go' in the terminal then in postman make a post request to "http://localhost:9000/users/signup" and in its body give email and password that creates a user then move on to login
that is post request to "http://localhost:9000/users/login" with the same body then copy the token you get and lets compose email with a post request to "http://localhost:9000/composemail" paste the token 
in this request header and in the body write the senderemail,recipientemail,subject and body and finally your email is composed.
Now if a user wants to see his recieved mails(inbox) then he can make a get request with his email and password like "http://localhost:9000/login/receivedMails/useremail/userpassword" replace useremail and 
userpassword with yours.Similarly a user can see his sent mails with "http://localhost:9000/login/sentMails/useremail/userpassword"
I have made two filtering options each for sent and received mails on the basis of sender and subject like to filter recieved mail on the basis of sender we can make a get request to
"http://localhost:9000/filterReceivedMailsOnSender/youremail/yourpassword/senderemail" replace youremail and yourpassword with your email and password and also sender email with email of the sender you want to see
Similarly all filtering options work
