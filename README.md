# How to Properly Refresh JWTs for Authentication in Golang

In this comprehensive guide, you'll learn how to properly refresh JSON Web Tokens (JWTs) using the RS256 algorithm and Redis. The integration of Redis will give us the ability to effortlessly revoke or invalidate the JWTs when necessary.

![How to Properly Refresh JWTs for Authentication in Golang](https://codevoweb.com/wp-content/uploads/2023/02/How-to-Properly-Refresh-JWTs-for-Authentication-in-Golang.webp)

## Topics Covered

- Run the Golang + Fiber JWT Project Locally
- Flaws of using only JWTs for Authentication
- Solutions to Address the Flaws of JWTs
- Bootstrap the Golang Project
- Setup Postgres, Redis, and pgAdmin with Docker
- Create the Database Model
- Connect to the Redis and Postgres Containers
    - Load the Environment Variables
    - Connect to the Redis Server
    - Connect to the Postgres Server
- Generate the Private and Public Keys
- Sign and Verify JWTs with the Asymmetric Keys
    - Sign the JWT with the Private Key
    - Verify the JWT with the Public Key
- Implement the JWT Authentication
    - Create the Account Registration Route Handler
    - Create the Account Login Route Handler
    - Create the Refresh Token Route Handler
    - Create the Logout Route Handler
- Create the JWT Middleware Guard
- Retrieve the Authentication User
- Register the Routes and Add CORS to the Server

Read the entire article here: [https://codevoweb.com/how-to-properly-use-jwt-for-authentication-in-golang/](https://codevoweb.com/how-to-properly-use-jwt-for-authentication-in-golang/)

