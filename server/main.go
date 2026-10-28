package main

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const maxBody = 2048

type tlsRequest struct {
	Host string `json:"host"`
}

type limiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-10 * time.Minute)
	kept := l.hits[key][:0]
	for _, hit := range l.hits[key] {
		if hit.After(cutoff) {
			kept = append(kept, hit)
		}
	}
	if len(kept) >= 12 {
		l.hits[key] = kept
		return false
	}
	l.hits[key] = append(kept, now)
	return true
}

func clientIP(request *http.Request) string {
	if forwarded := strings.TrimSpace(strings.Split(request.Header.Get("X-Forwarded-For"), ",")[0]); net.ParseIP(forwarded) != nil {
		return forwarded
	}
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return request.RemoteAddr
	}
	return host
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func main() {
	staticDir := os.Getenv("STATIC_DIR")
	if staticDir == "" {
		staticDir = "/srv"
	}
	limits := &limiter{hits: make(map[string][]time.Time)}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/tls-check", func(writer http.ResponseWriter, request *http.Request) {
		if !limits.allow(clientIP(request)) {
			writeJSON(writer, http.StatusTooManyRequests, map[string]string{"error": "检测请求过于频繁，请 10 分钟后重试。"})
			return
		}
		request.Body = http.MaxBytesReader(writer, request.Body, maxBody)
		defer request.Body.Close()
		var input tlsRequest
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "请求格式无效。"})
			return
		}
		ctx, cancel := context.WithTimeout(request.Context(), 15*time.Second)
		defer cancel()
		result, err := scan(ctx, input.Host)
		if err != nil {
			writeJSON(writer, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(writer, http.StatusOK, result)
	})
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		requestPath := pathpkg.Clean(request.URL.Path)
		if requestPath == "." || requestPath == "/" {
			requestPath = "index.html"
		} else {
			requestPath = strings.TrimPrefix(requestPath, "/")
		}
		candidate := filepath.Join(staticDir, filepath.FromSlash(requestPath))
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			candidate = filepath.Join(candidate, "index.html")
		}
		if info, err := os.Stat(candidate); err != nil || info.IsDir() {
			if strings.HasPrefix(requestPath, "tools/") || strings.HasPrefix(requestPath, "api/") {
				http.NotFound(writer, request)
				return
			}
			candidate = filepath.Join(staticDir, "index.html")
		}
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		writer.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		http.ServeFile(writer, request, candidate)
	})
	server := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	log.Printf("crypto toolbox listening on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}
