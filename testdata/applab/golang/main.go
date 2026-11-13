// Three small Go APIs, each with the request logger that its framework gives by default:
// gin (gin.Default), echo (middleware.Logger, JSON) and chi (middleware.Logger). The first argument picks one.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/labstack/echo/v4"
	echomiddleware "github.com/labstack/echo/v4/middleware"
)

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func check(c credentials, ip string) bool {
	if c.Username == "alice" && c.Password == "Summer2026!" {
		return true
	}
	log.Printf("Failed login for %s from %s", c.Username, ip)
	return false
}

func badItem(id string) bool {
	if strings.Contains(id, "'") {
		log.Printf(`pq: syntax error at or near "%s"`, id)
		return true
	}
	return false
}

func main() {
	switch os.Args[1] {
	case "gin":
		router := gin.Default()
		router.POST("/auth/login", func(c *gin.Context) {
			var body credentials
			_ = c.BindJSON(&body)
			if !check(body, c.ClientIP()) {
				c.JSON(401, gin.H{"error": "invalid credentials"})
				return
			}
			c.JSON(200, gin.H{"token": "t"})
		})
		router.GET("/api/items", func(c *gin.Context) {
			if badItem(c.Query("id")) {
				c.JSON(500, gin.H{"error": "server error"})
				return
			}
			c.JSON(200, []string{})
		})
		log.Fatal(router.Run(":8080"))
	case "echo":
		server := echo.New()
		server.Use(echomiddleware.Logger())
		server.POST("/auth/login", func(c echo.Context) error {
			var body credentials
			_ = c.Bind(&body)
			if !check(body, c.RealIP()) {
				return c.JSON(401, map[string]string{"error": "invalid credentials"})
			}
			return c.JSON(200, map[string]string{"token": "t"})
		})
		server.GET("/api/items", func(c echo.Context) error {
			if badItem(c.QueryParam("id")) {
				return c.JSON(500, map[string]string{"error": "server error"})
			}
			return c.JSON(200, []string{})
		})
		log.Fatal(server.Start(":8080"))
	case "chi":
		router := chi.NewRouter()
		router.Use(chimiddleware.Logger)
		router.Post("/auth/login", func(w http.ResponseWriter, r *http.Request) {
			var body credentials
			_ = json.NewDecoder(r.Body).Decode(&body)
			if !check(body, r.RemoteAddr) {
				http.Error(w, `{"error":"invalid credentials"}`, 401)
				return
			}
			w.Write([]byte(`{"token":"t"}`))
		})
		router.Get("/api/items", func(w http.ResponseWriter, r *http.Request) {
			if badItem(r.URL.Query().Get("id")) {
				http.Error(w, `{"error":"server error"}`, 500)
				return
			}
			w.Write([]byte(`[]`))
		})
		log.Fatal(http.ListenAndServe(":8080", router))
	}
}
