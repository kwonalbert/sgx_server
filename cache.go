// Cache maintains the map of ids to SGX sessions that this server
// currently possesses. Currently, we only have LRU policy
// implemented.
package sgx_server

import (
	"container/list"
	"sync"
)

type Cache interface {
	// Store the session under id key.
	Set(key string, session Session)

	// Get fetches the session correspoding to the session id key,
	// and returns (point to the session, true) if the id exsits.
	// Otherwise, Get returns (nil, false).
	Get(key string) (Session, bool)

	// Delete the entry if the key exists.
	Delete(key string)
}

type cache struct {
	sync.RWMutex

	capacity int
	queue    *list.List // back of the queue is the oldest
	items    map[string]*list.Element
}

func NewCache(capacity int) Cache {
	c := &cache{
		capacity: capacity,
		queue:    list.New(),
		items:    make(map[string]*list.Element),
	}
	return c
}

func (c *cache) Set(key string, session Session) {
	c.Lock()
	defer c.Unlock()
	elem := c.queue.PushFront(session)
	c.items[key] = elem

	// -1 indicates infinite capacity
	if c.queue.Len() > c.capacity && c.capacity != -1 {
		delete(c.items, c.queue.Back().Value.(Session).Id())
		c.queue.Remove(c.queue.Back())
	}
}

func (c *cache) Get(key string) (Session, bool) {
	c.RLock()
	defer c.RUnlock()
	elem, ok := c.items[key]
	if !ok {
		return nil, ok
	}
	c.queue.MoveToFront(elem)
	return elem.Value.(Session), true
}

func (c *cache) Delete(key string) {
	c.Lock()
	defer c.Unlock()
	elem, ok := c.items[key]
	if !ok { // if key's not in the cache, no problem
		return
	}

	c.queue.Remove(elem)
	delete(c.items, key)
}
