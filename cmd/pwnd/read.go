package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"net/http/pprof"
	"strconv"

	"code.tylerchr.com/tylerchr/pwnedpass"
)

// caphextable is used to hex-encode a string using capital letters. It's a
// slight variation to the strategy used by the stdlib's hex.Encode.
const caphextable = "0123456789ABCDEF"

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

	http.ListenAndServe(":8889", BuildHandler(od))

}

func BuildHandler(od *pwnedpass.OfflineDatabase) http.Handler {

	mux := http.NewServeMux()

	// mount pprof routes¡
	mux.Handle("/debug/pprof/", http.HandlerFunc(pprof.Index))

	// mount pwnedpassword endpoint
	mux.Handle("/pwnedpassword/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// get password
		pw := bytes.TrimPrefix([]byte(r.URL.Path), []byte("/pwnedpassword/"))

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
	mux.Handle("/range/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// get password
		prefix := bytes.TrimPrefix([]byte(r.URL.Path), []byte("/range/"))

		// validate hash
		if !isHashPrefix(prefix) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("The hash prefix was not in a valid format"))
			return
		}

		// produce the scan bounds
		var start, end [3]byte
		hex.Decode(start[:], append(prefix, byte('0')))
		hex.Decode(end[:], append(prefix, byte('F')))

		// perform the scan
		var hash [20]byte
		var hexhash [40]byte
		var buffer [64]byte
		response := bytes.NewBuffer(buffer[:])
		od.Scan(start, end, hash[:], func(freq int64) bool {

			// convert to capital hex bytes
			for i, v := range hash[:] {
				hexhash[i*2] = caphextable[v>>4]
				hexhash[i*2+1] = caphextable[v&0x0f]
			}

			response.Truncate(0)
			response.Write(hexhash[5:])
			response.Write([]byte{':'})
			response.WriteString(strconv.FormatInt(freq, 10))
			response.Write([]byte{'\r', '\n'})
			w.Write(response.Bytes())

			return false

		})

	}))

	return mux

}

// isHash indicates whether the given input is already a hash value,
// and returns it if so.
func isHash(s []byte) (hash [20]byte, ok bool) {

	// not a hash if it's not the right length
	if len(s) != 40 {
		ok = false
		return
	}

	// decode the hex bytes
	if _, err := hex.Decode(hash[:], s); err != nil {
		ok = false
		return
	}

	ok = true
	return

}

// isHashPrefix indicates whether s is a valid 5-character hex-encoded
// prefix suitable for use as the parameter to a range request.
func isHashPrefix(s []byte) bool {

	// not a hash prefix if it's not the right length
	if len(s) != 5 {
		// fmt.Printf("not the right length: %d\n", len(s))
		return false
	}

	for _, c := range s {
		isUpper := c >= 'A' && c <= 'Z'
		isLower := c >= 'a' && c <= 'z'
		isNum := c >= '0' && c <= '9'
		if !(isUpper || isLower || isNum) {
			// fmt.Printf("illegal character: %x (%c) (%t %t %t)\n", c, c, isUpper, isLower, isNum)
			return false
		}
	}

	return true

}
