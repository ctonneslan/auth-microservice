package main

import (
	"log"
	"os"
	"sync/atomic"
	"time"

	"github.com/ctonneslan/auth-microservice/handlers"
	"github.com/ctonneslan/auth-microservice/middleware"
	"github.com/ctonneslan/auth-microservice/store"
	"github.com/gin-gonic/gin"
)

var requestCount atomic.Int64
var startTime = time.Now()

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "dev-secret-change-in-production"
	}

	s := store.New()
	auth := handlers.NewAuthHandler(s, jwtSecret)

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(middleware.StructuredLogger())

	// Health and metrics
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	r.GET("/metrics", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"uptime_seconds": time.Since(startTime).Seconds(),
			"total_requests": requestCount.Load(),
			"total_users":    s.UserCount(),
		})
	})

	// Request counter middleware
	r.Use(func(c *gin.Context) {
		requestCount.Add(1)
		c.Next()
	})

	// Public routes with rate limiting
	public := r.Group("/auth")
	public.Use(middleware.RateLimit(20, time.Minute))
	{
		public.POST("/register", auth.Register)
		public.POST("/login", auth.Login)
		public.POST("/refresh", auth.Refresh)
	}

	// Protected routes
	protected := r.Group("/api")
	protected.Use(middleware.JWTAuth([]byte(jwtSecret)))
	{
		protected.GET("/me", auth.Me)

		// Admin-only routes
		admin := protected.Group("/admin")
		admin.Use(middleware.RequireRole("admin"))
		{
			admin.GET("/stats", func(c *gin.Context) {
				c.JSON(200, gin.H{
					"total_users":    s.UserCount(),
					"total_requests": requestCount.Load(),
					"uptime_seconds": time.Since(startTime).Seconds(),
				})
			})
		}
	}

	log.Printf("Auth microservice starting on :%s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
