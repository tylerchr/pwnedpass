package main

import (
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"code.tylerchr.com/tylerchr/pwnedpass"
)

func BenchmarkServerPassword(b *testing.B) {

	// open the offline database
	od, err := pwnedpass.NewOfflineDatabase("../../" + pwnedpass.DatabaseFilename)
	if err != nil {
		panic(err)
	}
	defer od.Close()

	// start a dummy HTTP server
	s := httptest.NewServer(BuildHandler(od))
	defer s.Close()

	// run a benchmark
	b.ResetTimer()
	for i := 0; i < b.N; i++ {

		req, _ := http.NewRequest("GET", s.URL+"/pwnedpassword/P@ssword", nil)

		resp, err := s.Client().Do(req)
		if err != nil {
			b.Fatalf("unexpected error: %s\n", err)
		}

		if n, err := io.Copy(ioutil.Discard, resp.Body); err != nil {
			b.Fatalf("unexpected error: %s\n", err)
		} else if n != 24 {
			b.Fatalf("unexpected response length: %d\n", n)
		}

		resp.Body.Close()

	}

}

func BenchmarkServerRange(b *testing.B) {

	// open the offline database
	od, err := pwnedpass.NewOfflineDatabase("../../" + pwnedpass.DatabaseFilename)
	if err != nil {
		panic(err)
	}
	defer od.Close()

	// start a dummy HTTP server
	s := httptest.NewServer(BuildHandler(od))
	defer s.Close()

	// run a benchmark
	b.ResetTimer()
	for i := 0; i < b.N; i++ {

		req, _ := http.NewRequest("GET", s.URL+"/range/abcde", nil)

		resp, err := s.Client().Do(req)
		if err != nil {
			b.Fatalf("unexpected error: %s\n", err)
		}

		if n, err := io.Copy(ioutil.Discard, resp.Body); err != nil {
			b.Fatalf("unexpected error: %s\n", err)
		} else if n != 19957 {
			b.Fatalf("unexpected response length: %d\n", n)
		}

		resp.Body.Close()

	}

}
