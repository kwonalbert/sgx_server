package sgx_server

import "testing"

func nilSession(id uint64) *Session {
	return NewSession(id, nil, 0, nil, nil, nil)
}

func TestLRUCache(t *testing.T) {
	cache := NewCache(2)
	cache.Set(0, nilSession(0))
	cache.Set(1, nilSession(1))

	if _, ok := cache.Get(0); !ok {
		t.Fatal("Could not find the first element.")
	}

	if _, ok := cache.Get(1); !ok {
		t.Fatal("Could not find the second element.")
	}

	cache.Set(2, nilSession(2))
	if _, ok := cache.Get(2); !ok {
		t.Fatal("Could not find the third element.")
	}

	if _, ok := cache.Get(0); ok {
		t.Fatal("The first element should have been evicted.")
	}
}
