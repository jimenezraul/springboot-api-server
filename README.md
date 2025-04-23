# Spring Boot Secure API Server

A robust RESTful API server built with **Spring Boot**, designed with a strong focus on **security, scalability, and maintainability**. This project implements **JWT-based authentication**, **role-based access control**, and best practices for securing modern API backends.

---

## 🔗 Table of Contents

- [Features](#features)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
    - [Configuration](#configuration)
    - [Running the Application](#running-the-application)
- [API Endpoints](#api-endpoints)
    - [Authentication](#authentication)
    - [User Management](#user-management)
- [Security Details](#security-details)
- [Database Seeding](#database-seeding)
- [License](#license)

---

## 🎯 Features

- **JWT Authentication** – Secure access & refresh token flow
- **Spring Security** – Stateless sessions with custom filters
- **Role-Based Access Control** – Admin/user route protection
- **Token Refresh Endpoint** – Safe renewal of access tokens
- **Secure Password Storage** – BCrypt hashing
- **Cookie Handling** – `Cookies` utility to set/delete HTTP-only cookies
- **SHA-256 Hashing** – `Sha256Hasher` for refresh token storage
- **Global Exception Handling** – Consistent error responses
- **CORS Configuration** – Enable frontend-backend communication
- **Database Seeding** – `SeedData` for initial data loading
- **Clean Architecture** – Separation of controllers, services, DTOs, entities

---

## 🛠️ Tech Stack

- **Language:** Java 21+
- **Framework:** Spring Boot 3
- **Security:** Spring Security, JWT (jjwt)
- **Database:** MySQL
- **ORM:** Spring Data JPA + Hibernate
- **Build Tool:** Maven
- **Validation:** Jakarta Bean Validation

---

## 🚀 Getting Started

### Prerequisites

- Java 21+
- Maven 3.6+
- MySQL

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/jimenezraul/springboot-api-server.git
   cd springboot-api-server
   ```

2. **Build the project**
   ```bash
   mvn clean install
   ```

### Configuration

Duplicate `env.example.properties` to `env.properties` and update:

```properties
#****************************************************************************************************
# Database configuration
#****************************************************************************************************
DATABASE_URL=<your-database-url>
DB_USERNAME=<your-username>
DB_PASSWORD=<your-password>

#****************************************************************************************************
# JWT configuration
#****************************************************************************************************
PUBLIC_KEY=<your-public-key>
PRIVATE_KEY=<your-private-key>
REFRESH_PRIVATE_KEY=<your-refresh-private-key>
REFRESH_PUBLIC_KEY=<your-refresh-public-key>
```

### Running the Application

```bash
mvn spring-boot:run
```

The API will be available at `http://localhost:8080`.

---

## 📦 API Endpoints

### Authentication

| Method | Endpoint       | Description                       | Auth Required |
|--------|----------------|-----------------------------------|---------------|
| POST   | `/api/v1/auth/login`    | Login and receive tokens         | ❌            |
| POST   | `/api/v1/auth/refresh`  | Refresh access token using refreshToken cookie | ❌ |
| POST   | `/api/v1/auth/logout`   | Clear token cookies              | ✅            |

### User Me Data

| Method | Endpoint            | Description               | Auth Required     |
|--------|---------------------|---------------------------|-------------------|
| GET    | `/api/v1/me`     | Get current user profile  | ✅ (access token) |

---

## 🛡️ Security Details

- **JWT Flow**: Access & Refresh tokens issued on login; stored in **HTTP-only cookies** via `Cookies.setTokenCookies()`.
- **Token Validation**: Custom filter checks `Authorization: Bearer <token>` header or cookies.
- **Refresh Token Hashing**: Stored hashed in DB using `Sha256Hasher` for security.
- **Role Enforcement**: `@PreAuthorize` and Spring Security config enforce role-based access.

---

## 💾 Database Seeding

- Hibernate auto-creates schema (`ddl-auto: create`).
- `SeedData` in `src/main/java/com/api_server/API/Server` seeds default roles (`ROLE_OWNER`, `ROLE_STAFF`, `ROLE_ADMIN`) and initial admin user.

---

## 📄 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

