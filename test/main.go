package main

import (
	"fmt"
	"log"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	fmt.Fprintf(w, "Hello, %s\n", clientIP)
}

func main() {
	http.HandleFunc("/", handler)
	fmt.Println("Starting server on :8000")
	err := http.ListenAndServe(":8000", nil)
	if err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
