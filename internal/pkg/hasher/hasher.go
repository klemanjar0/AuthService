package hasher

import (
	"golang.org/x/crypto/bcrypt"
)

type Hasher interface {
	Hash(password string) (string, error)
	Compare(hashedPassword, password string) bool
}

type bcryptHasher struct {
	cost int
}

func NewBcryptHasher(cost int) Hasher {
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}
	return &bcryptHasher{cost: cost}
}

func (h *bcryptHasher) Hash(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func (h *bcryptHasher) Compare(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}
