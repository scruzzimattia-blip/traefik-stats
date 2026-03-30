package main

import (
	"database/sql"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

type CacheEntry struct {
	Blocked bool
	Reason  string
	Expiry  time.Time
}

var (
	cache      = make(map[string]CacheEntry)
	cacheMutex sync.RWMutex
	db         *sql.DB
)

func getCache(ip string) (bool, string, bool) {
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()
	entry, ok := cache[ip]
	if ok && time.Now().Before(entry.Expiry) {
		return entry.Blocked, entry.Reason, true
	}
	return false, "", false
}

func setCache(ip string, blocked bool, reason string, duration time.Duration) {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()
	cache[ip] = CacheEntry{
		Blocked: blocked,
		Reason:  reason,
		Expiry:  time.Now().Add(duration),
	}
}

func logEvent(ip, reason, target, ua string) {
	if db == nil {
		return
	}
	_, err := db.Exec(
		"INSERT INTO bouncer_events (timestamp, ip_address, reason, target_url, user_agent) VALUES ($1, $2, $3, $4, $5)",
		time.Now(), ip, reason, target, ua,
	)
	if err != nil {
		fmt.Printf("Error logging event to DB: %v\n", err)
	}
}

func main() {
	lapiURL := os.Getenv("CROWDSEC_LAPI_URL")
	if lapiURL == "" {
		lapiURL = "http://traefik-stats-crowdsec:8080"
	}
	lapiKey := os.Getenv("CROWDSEC_LAPI_KEY")
	redirectURL := os.Getenv("REDIRECT_URL")
	if redirectURL == "" {
		redirectURL = "https://blocked.scruzzi.com"
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL != "" {
		var err error
		db, err = sql.Open("postgres", dbURL)
		if err != nil {
			fmt.Printf("Error connecting to DB: %v\n", err)
		} else {
			db.SetMaxOpenConns(5)
			db.SetMaxIdleConns(2)
			db.SetConnMaxLifetime(5 * time.Minute)
			fmt.Println("Connected to Database for Audit Logging")
		}
	}

	fmt.Println("Starting Updated CrowdSec Bouncer (with Cache & DB Logging) on :8080")
	fmt.Printf("LAPI URL: %s\n", lapiURL)
	fmt.Printf("Redirect URL: %s\n", redirectURL)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		clientIP := ""
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			ips := strings.Split(xff, ",")
			clientIP = strings.TrimSpace(ips[0])
		}
		if clientIP == "" {
			clientIP = r.Header.Get("X-Real-IP")
		}
		if clientIP == "" {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err == nil {
				clientIP = host
			} else {
				clientIP = r.RemoteAddr
			}
		}

		ua := r.Header.Get("User-Agent")

		// Check cache first
		if blocked, reason, ok := getCache(clientIP); ok {
			if blocked {
				fmt.Printf("Cached Block: %s\n", clientIP)
				w.Header().Set("X-Crowdsec-Decision", "ban")
				target := fmt.Sprintf("%s?ip=%s&reason=%s", 
					redirectURL, clientIP, strings.ReplaceAll(reason, " ", "+"))
				
				go logEvent(clientIP, reason, target, ua)
				
				http.Redirect(w, r, target, http.StatusFound)
				return
			}
			w.Header().Set("X-Crowdsec-Decision", "none")
			w.WriteHeader(http.StatusOK)
			return
		}

		url := fmt.Sprintf("%s/v1/decisions?ip=%s", lapiURL, clientIP)
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("X-Api-Key", lapiKey)

		client := &http.Client{Timeout: 1 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("Error querying LAPI: %v\n", err)
			w.Header().Set("X-Crowdsec-Decision", "none")
			w.WriteHeader(http.StatusOK)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(resp.Body)
			if len(body) > 4 { 
				reason := "Security Policy Violation"
				reasonIdx := strings.Index(string(body), "\"reason\":\"")
				if reasonIdx != -1 {
					start := reasonIdx + 10
					end := strings.Index(string(body)[start:], "\"")
					if end != -1 {
						reason = string(body)[start : start+end]
					}
				}

				fmt.Printf("New Block: %s (%s)\n", clientIP, reason)
				setCache(clientIP, true, reason, 30*time.Second)
				
				w.Header().Set("X-Crowdsec-Decision", "ban")
				target := fmt.Sprintf("%s?ip=%s&reason=%s", 
					redirectURL, clientIP, strings.ReplaceAll(reason, " ", "+"))
				
				go logEvent(clientIP, reason, target, ua)
				
				http.Redirect(w, r, target, http.StatusFound)
				return
			}
		}

		// Cache "clean" IPs for 1 minute
		setCache(clientIP, false, "", 1*time.Minute)
		w.Header().Set("X-Crowdsec-Decision", "none")
		w.WriteHeader(http.StatusOK)
	})

	http.ListenAndServe(":8080", nil)
}
