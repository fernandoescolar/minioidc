package stores

import (
	"testing"
	"time"
)

func TestUserBlockedStore(t *testing.T) {
	store := NewUserBlockedStoreWithPolicy(3, time.Minute, 10*time.Minute)
	now := time.Now()

	if store.AddFailedAttempt("user", now) || store.AddFailedAttempt("user", now) {
		t.Fatal("Expected not to block before the max attempts")
	}

	if !store.AddFailedAttempt("user", now) || !store.IsBlocked("user", now) {
		t.Fatal("Expected to block after the max attempts")
	}

	if store.IsBlocked("another", now) {
		t.Error("Expected other keys not to be blocked")
	}

	if store.IsBlocked("user", now.Add(11*time.Minute)) {
		t.Error("Expected the block to expire")
	}

	store.AddFailedAttempt("slow", now)
	store.AddFailedAttempt("slow", now)
	if store.AddFailedAttempt("slow", now.Add(2*time.Minute)) {
		t.Error("Expected failed attempts outside the window not to be counted")
	}

	store.Reset("slow")
	store.CleanExpired(now.Add(time.Hour))
	if store.IsBlocked("user", now.Add(time.Hour)) {
		t.Error("Expected no blocks after clean")
	}
}
