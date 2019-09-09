package sgx_server

import (
	"container/list"
	"sync"
)

type cache struct {
	sync.RWMutex

	capacity int
	// back is the oldest
	queue *list.List
	items map[uint64]*list.Element
}

func NewCache(capacity int) *cache {
	c := &cache{
		capacity: capacity,
		queue:    list.New(),
		items:    make(map[uint64]*list.Element),
	}
	return c
}

func (c *cache) Set(key uint64, session *Session) {
	c.Lock()
	defer c.Unlock()
	elem := c.queue.PushFront(session)
	c.items[key] = elem

	// -1 indicates infinite capacity
	if c.queue.Len() > c.capacity && c.capacity != -1 {
		delete(c.items, c.queue.Back().Value.(*Session).id)
		c.queue.Remove(c.queue.Back())
	}
}

func (c *cache) Get(key uint64) (*Session, bool) {
	c.RLock()
	defer c.RUnlock()
	elem, ok := c.items[key]
	if !ok {
		return nil, ok
	}
	c.queue.MoveToFront(elem)
	return elem.Value.(*Session), true
}

func (c *cache) Delete(key uint64) {
	c.Lock()
	defer c.Unlock()
	elem, ok := c.items[key]
	if !ok { // if key's not in the cache, no problem
		return
	}

	c.queue.Remove(elem)
	delete(c.items, key)
}
