// Command webhook-receiver is the lab's webhook endpoint (§11.1, §7.5): it
// checks each request's signature and age as a real receiver should, and
// appends what it received to a file, one JSON object per line, for the tests
// to read. It computes the HMAC itself instead of calling notify.Sign, so
// that a change of the format in ligo does not go unnoticed.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// maxAge is how old, or how far ahead, a timestamp may be (§7.5).
const maxAge = 5 * time.Minute

// record is one request received.
type record struct {
	Hook      string `json:"hook"`
	Verdict   string `json:"verdict"`
	Timestamp string `json:"timestamp"`
	Body      string `json:"body"`
}

// verdict judges a request: "ok", "bad-timestamp", "stale" or "bad-signature".
func verdict(secret []byte, timestamp, signature string, body []byte, now time.Time) string {
	sec, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return "bad-timestamp"
	}
	if now.Sub(time.Unix(sec, 0)).Abs() > maxAge {
		return "stale"
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(timestamp + "."))
	mac.Write(body)
	if !hmac.Equal([]byte("sha256="+hex.EncodeToString(mac.Sum(nil))), []byte(signature)) {
		return "bad-signature"
	}
	return "ok"
}

// handler serves POST /hooks/{name}; secret gives a hook's secret, "" for an
// unknown hook. Anything but a valid request gets 401, so that ligo retries
// and the failure shows.
func handler(secret func(hook string) string, out io.Writer, now func() time.Time) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /hooks/{name}", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rec := record{Hook: r.PathValue("name"), Verdict: "unknown-hook", Timestamp: r.Header.Get("X-Ligo-Timestamp"), Body: string(body)}
		if s := secret(rec.Hook); s != "" {
			rec.Verdict = verdict([]byte(s), rec.Timestamp, r.Header.Get("X-Ligo-Signature"), body, now())
		}
		line, err := json.Marshal(rec)
		if err == nil {
			_, err = out.Write(append(line, '\n')) // one write per line: O_APPEND keeps lines whole
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if rec.Verdict != "ok" {
			http.Error(w, rec.Verdict, http.StatusUnauthorized)
		}
	})
	return mux
}

func main() {
	listen := flag.String("listen", ":8443", "address to listen on")
	cert := flag.String("cert", "", "TLS certificate file")
	key := flag.String("key", "", "TLS key file")
	path := flag.String("log", "", "file to append the requests to")
	flag.Parse()
	out, err := os.OpenFile(*path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640) //nolint:gosec // a path from the lab's unit
	if err != nil {
		log.Fatal(err)
	}
	secret := func(hook string) string { return os.Getenv("HOOK_SECRET_" + strings.ToUpper(hook)) }
	srv := &http.Server{Addr: *listen, Handler: handler(secret, out, time.Now), ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServeTLS(*cert, *key))
}
