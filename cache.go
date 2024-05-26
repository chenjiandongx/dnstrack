package main

import (
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

type cache struct {
	m *expirable.LRU[string, time.Time]
}

func newCache() *cache {
	return &cache{
		m: expirable.NewLRU[string, time.Time](65535, nil, 0),
	}
}

func (c *cache) get(k string) (time.Time, bool) {
	v, ok := c.m.Get(k)
	return v, ok
}

func (c *cache) set(k string, v time.Time) {
	c.m.Add(k, v)
}
