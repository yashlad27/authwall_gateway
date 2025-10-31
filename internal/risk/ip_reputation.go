package risk

import (
	"sync"
)

// InMemoryIPReputation implements a simple in-memory IP reputation database
type InMemoryIPReputation struct {
	mu          sync.RWMutex
	blacklist   map[string]bool
	reputation  map[string]float64
}

// NewInMemoryIPReputation creates a new in-memory IP reputation database
func NewInMemoryIPReputation() *InMemoryIPReputation {
	return &InMemoryIPReputation{
		blacklist:  make(map[string]bool),
		reputation: make(map[string]float64),
	}
}

// CheckReputation checks the reputation score of an IP (0-100)
func (db *InMemoryIPReputation) CheckReputation(ip string) (float64, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	if score, exists := db.reputation[ip]; exists {
		return score, nil
	}

	// Default reputation for unknown IPs
	return 50.0, nil
}

// IsBlacklisted checks if an IP is blacklisted
func (db *InMemoryIPReputation) IsBlacklisted(ip string) (bool, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return db.blacklist[ip], nil
}

// AddToBlacklist adds an IP to the blacklist
func (db *InMemoryIPReputation) AddToBlacklist(ip string) {
	db.mu.Lock()
	defer db.mu.Unlock()

	db.blacklist[ip] = true
	db.reputation[ip] = 100.0 // Maximum risk
}

// RemoveFromBlacklist removes an IP from the blacklist
func (db *InMemoryIPReputation) RemoveFromBlacklist(ip string) {
	db.mu.Lock()
	defer db.mu.Unlock()

	delete(db.blacklist, ip)
	delete(db.reputation, ip)
}

// SetReputation sets the reputation score for an IP
func (db *InMemoryIPReputation) SetReputation(ip string, score float64) {
	db.mu.Lock()
	defer db.mu.Unlock()

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	db.reputation[ip] = score
}

// UpdateReputation adjusts the reputation score of an IP
func (db *InMemoryIPReputation) UpdateReputation(ip string, delta float64) {
	db.mu.Lock()
	defer db.mu.Unlock()

	currentScore := db.reputation[ip]
	if currentScore == 0 {
		currentScore = 50.0 // Default starting point
	}

	newScore := currentScore + delta
	if newScore < 0 {
		newScore = 0
	}
	if newScore > 100 {
		newScore = 100
	}

	db.reputation[ip] = newScore
}
