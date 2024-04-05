package main

import (
	"serve/server"
	"serve/store"
	"sync"
)

func main() {
	var wg sync.WaitGroup
	wg.Add(1)
	mongoStore := store.NewMongoStore()

	go func() {
		defer wg.Done()
		server.Performserver(mongoStore)
	}()
	wg.Wait()

}
