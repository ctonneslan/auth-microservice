package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type rateLimiter struct {
	mu       sync.Mutex
	clients  map[string]*clientInfo
	limit    int
	window   time.Duration
}

type clientInfo struct {
	count    int
	resetAt  time.Time
}

func RateLimit(limit int, window time.Duration) gin.HandlerFunc {
	rl := &rateLimiter{
		clients: make(map[string]*clientInfo),
		limit:   limit,
		window:  window,
	}

	// Cleanup goroutine
	go func() {
		for {
			time.Sleep(window)
			rl.mu.Lock()
			now := time.Now()
			for ip, info := range rl.clients {
				if now.After(info.resetAt) {
					delete(rl.clients, ip)
				}
			}
			rl.mu.Unlock()
		}
	}()

	return func(c *gin.Context) {
		ip := c.ClientIP()

		rl.mu.Lock()
		info, exists := rl.clients[ip]
		if !exists || time.Now().After(info.resetAt) {
			rl.clients[ip] = &clientInfo{
				count:   1,
				resetAt: time.Now().Add(window),
			}
			rl.mu.Unlock()
			c.Next()
			return
		}

		if info.count >= rl.limit {
			rl.mu.Unlock()
			retryAfter := time.Until(info.resetAt).Seconds()
			c.Header("Retry-After", string(rune(int(retryAfter))))
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "rate limit exceeded",
				"retry_after": int(retryAfter),
			})
			c.Abort()
			return
		}

		info.count++
		rl.mu.Unlock()
		c.Next()
	}
}
