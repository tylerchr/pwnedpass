package main

import (
	"crypto/sha1"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"strings"
	"time"

	"code.tylerchr.com/tylerchr/pwnedpass"
)

func main() {

	// parse flags
	var dbFile string
	flag.StringVar(&dbFile, "database", pwnedpass.DatabaseFilename, "path to the database file")
	flag.Parse()

	// open the offline database
	od, err := pwnedpass.NewOfflineDatabase(dbFile)
	if err != nil {
		panic(err)
	}
	defer od.Close()

	// mount pwnedpassword endpoint
	http.Handle("/pwnedpassword/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		t0 := time.Now()
		defer func() { fmt.Printf("[%s] Responded in %s\n", r.URL, time.Since(t0)) }()

		// get password
		pw := strings.TrimPrefix(r.URL.Path, "/pwnedpassword/")

		var hash [20]byte
		if hh, ok := isHash(pw); ok {
			// already a hash, just use it
			hash = hh
		} else {
			// not a hash, hash it now
			hash = sha1.Sum([]byte(pw))
		}

		w.Header().Set("X-Password-SHA1", hex.EncodeToString(hash[:]))

		frequency, err := od.Pwned(hash)
		if err != nil {
			fmt.Printf("unexpected error: %s\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if frequency == 0 {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintln(w, "Password not compromised")
		} else {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "Compromised: %d times\n", frequency)
		}

	}))

	// mount range endpoint
	http.Handle("/range/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		t0 := time.Now()
		defer func() { fmt.Printf("[%s] Responded in %s\n", r.URL, time.Since(t0)) }()

		// get password
		prefix := strings.TrimPrefix(r.URL.Path, "/range/")

		if !isHashPrefix(prefix) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("The hash prefix was not in a valid format"))
			return
		}

		// produce the scan bounds
		var start, end [3]byte
		ss, _ := hex.DecodeString(prefix + "0")
		ee, _ := hex.DecodeString(prefix + "F")
		copy(start[:], ss)
		copy(end[:], ee)

		// perform the scan
		od.Scan(start, end, func(hash [20]byte, freq uint16) bool {
			fmt.Fprintf(w, "%s:%d\r\n", strings.TrimPrefix(strings.ToUpper(hex.EncodeToString(hash[:])), prefix), freq)
			return false
		})

	}))

	http.ListenAndServe(":8889", nil)

}

// isHash indicates whether the given input is already a hash value,
// and returns it if so.
func isHash(s string) (hash [20]byte, ok bool) {

	// not a hash if it's not the right length
	if len(s) != 40 {
		ok = false
		return
	}

	ss, err := hex.DecodeString(s)
	if err != nil {
		ok = false
		return
	}

	copy(hash[:], ss)
	ok = true
	return

}

// isHashPrefix indicates whether s is a valid 5-character hex-encoded
// prefix suitable for use as the parameter to a range request.
func isHashPrefix(s string) bool {

	// not a hash prefix if it's not the right length
	if len(s) != 5 {
		fmt.Printf("not the right length: %d\n", len(s))
		return false
	}

	for _, c := range []byte(s) {
		isUpper := c >= 'A' && c <= 'Z'
		isLower := c >= 'a' && c <= 'z'
		isNum := c >= '0' && c <= '9'
		if !(isUpper || isLower || isNum) {
			fmt.Printf("illegal character: %x (%c) (%t %t %t)\n", c, c, isUpper, isLower, isNum)
			return false
		}
	}

	return true

}
