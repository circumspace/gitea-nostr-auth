package handler

import "net/http"

// noStore marks a response as uncacheable (RFC 6749 5.1).
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}
