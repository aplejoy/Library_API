# Library Management API

Library Management API developed with PHP and the Slim framework. It features endpoints for user registration, authentication, and managing authors and books. The API leverages JSON Web Tokens (JWT) for secure authentication and token handling.

##Features 

- **User Management:** The user can Register, Authenticate, Show, Update, and Delete Users
- **Author Management:** The user can Register, Show, Update, and Delete Authors
- **Book Management:** The user can Register, Show, Update, and Delete Books
- **Book Authors:** The user can Register, Show, Update, and Delete Book Authors
- **Token Management:** The user can Generate, Validate

##Requirements

-PHP 7.4 or higher
-MySQLyog
-XAMPP
-SLIM
-Git
-Firebase
-Composer
-Node.js

##Installation

1. Clone the Repository:
'git clone https://github.com/aplejoy/Library_API.git'
'cd Library_API'
2. Install dependencies:
'composer require slim/slim:3.*'
'composer require firebase/php-jwt'

##API Endpoints

###User Management
**Register User**:
-**Endpoint:** '/user/register'
-**Method:** 'POST'
-**Payload:** 
'{
  "username": "your_username",
  "password": "your_password"
}'

**Authenticate User**:
-**Endpoint:** '/user/auth'
-**Method:** 'POST'
-**Payload:** 
'{
  "username": "your_username",
  "password": "your_password"
}'

**Show Users**:
-**Endpoint:** '/user/show'
-**Method:** 'GET'
-**Payload:** 
'{
  "Authorization": "Bearer your_token"
}'

**Update User**:
-**Endpoint:** '/user/update'
-**Method:** 'PUT'
-**Payload:** 
'{
  "token": "your_token",
  "userid": "your_userid",
  "username": "your_new_username",
  "password": "your_new_password"
}'

**Delete Users**:
-**Endpoint:** '/user/delete'
-**Method:** 'DELETE'
-**Payload:** 
'{
  "token": "your_token",
  "userid": "your_userid"
}'

###Author Management
**Register Author**:
-**Endpoint:** '/author/register'
-**Method:** 'POST'
-**Payload:** 
'{
  "token": "your_token",
  "name": "author_name"
}'

**Show Authors**:
-**Endpoint:** '/author/show'
-**Method:** 'GET'
-**Payload:** 
'{
  "Authorization": "Bearer your_token"
}'

**Update Author**:
-**Endpoint:** '/author/update'
-**Method:** 'PUT'
-**Payload:** 
'{
  "token": "your_token",
  "authorid": "author_id",
  "name": "author_name"
}'

**Delete Author**:
-**Endpoint:** '/author/delete'
-**Method:** 'DELETE'
-**Payload:** 
'{
  "token": "your_token",
  "authorid": "author_id"
}'

###Book Management
**Register Book**:
-**Endpoint:** '/book/register'
-**Method:** 'POST'
-**Payload:** 
'{
  "token": "your_jwt_token",
  "title": "book_title",
  "authorid": 1
}'

**Show Books**:
-**Endpoint:** '/book/show'
-**Method:** 'GET'
-**Payload:** 
'{
  "Authorization": "Bearer your_token"
}'

**Update Book**:
-**Endpoint:** '/book/update'
-**Method:** 'PUT'
-**Payload:** 
'{
  "token": "your_jwt_token",
  "bookid": 1,
  "title": "new_book_title",
  "authorid": 1
}'

**Delete Book**:
-**Endpoint:** '/book/delete'
-**Method:** 'DELETE'
-**Payload:** 
'{
  "token": "your_jwt_token",
  "bookid": 1
}'

###Book Authors Management
**Register Book Author**:
-**Endpoint:** '/book_author/register'
-**Method:** 'POST'
-**Payload:** 
'{
  "token": "your_jwt_token",
  "bookid": 1,
  "authorid": 1
}'

**Show Book Authors**:
-**Endpoint:** '/book_author/show'
-**Method:** 'GET'
-**Payload:** 
'{
  "Authorization": "Bearer your_token"
}'

**Update Book Author**:
-**Endpoint:** '/book_author/update'
-**Method:** 'PUT'
-**Payload:** 
'{
  "token": "your_jwt_token",
  "collectionid": 1,
  "bookid": 1,
  "authorid": 1
}'

**Delete Book Author**:
-**Endpoint:** '/book_author/delete'
-**Method:** 'DELETE'
-**Payload:** 
'{
  "token": "your_jwt_token",
  "collectionid": 1
}'

##Token Management
-**Generate a Token:** Tokens are created during user authentication and recorded in the tokens table with an 'active' status.
-**Validate the Token:** The validateToken function is used to verify tokens by checking their status and decoding them to extract the user ID.
