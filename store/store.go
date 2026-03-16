package store

import (
	"errors"
	"sync"
	"time"

	"github.com/ctonneslan/auth-microservice/models"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUserExists   = errors.New("user already exists")
	ErrUserNotFound = errors.New("user not found")
	ErrInvalidCreds = errors.New("invalid credentials")
)

// MemoryStore is a thread-safe in-memory user store.
// In production, replace with PostgreSQL/Redis.
type MemoryStore struct {
	mu            sync.RWMutex
	users         map[string]*models.User
	emailIndex    map[string]string // email -> user ID
	refreshTokens map[string]string // token -> user ID
}

func New() *MemoryStore {
	return &MemoryStore{
		users:         make(map[string]*models.User),
		emailIndex:    make(map[string]string),
		refreshTokens: make(map[string]string),
	}
}

func (s *MemoryStore) CreateUser(req models.RegisterRequest) (*models.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.emailIndex[req.Email]; exists {
		return nil, ErrUserExists
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil {
		return nil, err
	}

	role := req.Role
	if role == "" {
		role = "user"
	}

	user := &models.User{
		ID:             uuid.New().String(),
		Email:          req.Email,
		Name:           req.Name,
		HashedPassword: string(hashed),
		Role:           role,
		CreatedAt:      time.Now(),
	}

	s.users[user.ID] = user
	s.emailIndex[user.Email] = user.ID

	return user, nil
}

func (s *MemoryStore) Authenticate(email, password string) (*models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	userID, exists := s.emailIndex[email]
	if !exists {
		return nil, ErrInvalidCreds
	}

	user := s.users[userID]
	if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(password)); err != nil {
		return nil, ErrInvalidCreds
	}

	return user, nil
}

func (s *MemoryStore) GetUser(id string) (*models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[id]
	if !exists {
		return nil, ErrUserNotFound
	}
	return user, nil
}

func (s *MemoryStore) StoreRefreshToken(token, userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshTokens[token] = userID
}

func (s *MemoryStore) ValidateRefreshToken(token string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	userID, exists := s.refreshTokens[token]
	return userID, exists
}

func (s *MemoryStore) RevokeRefreshToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.refreshTokens, token)
}

func (s *MemoryStore) UserCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users)
}
