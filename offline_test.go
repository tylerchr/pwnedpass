package pwnedpass

import (
	"crypto/sha1"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPwned(t *testing.T) {

	cases := []struct {
		Password  string
		Frequency int
	}{
		{
			Password:  "P@ssword",
			Frequency: 10664,
		},
		{
			Password:  "775f96123edda7b3bc918bb155757d58df98246e",
			Frequency: 0,
		},
	}

	od, err := NewOfflineDatabase(DatabaseFilename, UpdatedDatabaseFilename)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	for i, c := range cases {

		if frequency, err := od.Pwned(sha1.Sum([]byte(c.Password))); err != nil {
			t.Fatalf("[case %d] unexpected error: %s", i, err)
		} else if frequency != c.Frequency {
			t.Errorf("[case %d] unexpected frequency: expected '%d' but got '%d'", i, c.Frequency, frequency)
		}

	}

}

func BenchmarkPwned(b *testing.B) {

	od, err := NewOfflineDatabase(DatabaseFilename, UpdatedDatabaseFilename)
	if err != nil {
		b.Fatalf("unexpected error: %s", err)
	}

	hash := sha1.Sum([]byte("P@ssword"))

	b.ResetTimer()

	for i := 0; i < b.N; i++ {

		if _, err := od.Pwned(hash); err != nil {
			b.Fatalf("[case %d] unexpected error: %s", i, err)
		}

	}

}

func TestScan(t *testing.T) {

	cases := []struct {
		StartPrefix, EndPrefix [3]byte
		UseCutoffPrefix        bool
		CutoffPrefix           [3]byte // the prefix at which to terminate execution via the callback
		Hashes                 int
	}{
		{
			StartPrefix: [3]byte{0x00, 0x00, 0x00},
			EndPrefix:   [3]byte{0x00, 0x00, 0x00},
			Hashes:      145,
		},
		{
			StartPrefix: [3]byte{0x05, 0x31, 0x91},
			EndPrefix:   [3]byte{0x05, 0x31, 0x91},
			Hashes:      68,
		},
		{
			StartPrefix: [3]byte{0x05, 0x31, 0x91},
			EndPrefix:   [3]byte{0x05, 0x31, 0x92},
			Hashes:      124,
		},
		{
			StartPrefix: [3]byte{0xFF, 0xFF, 0xFF},
			EndPrefix:   [3]byte{0xFF, 0xFF, 0xFF},
			Hashes:      46,
		},
	}

	od, err := NewOfflineDatabase(DatabaseFilename, UpdatedDatabaseFilename)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	for i, c := range cases {

		var count int
		var hash [20]byte

		err = od.Scan(c.StartPrefix, c.EndPrefix, hash[:], func(freq uint16) bool {
			count++
			return false
		})

		if err != nil {
			t.Fatalf("[case %d] unexpected error: %s", i, err)
		}

		if count != c.Hashes {
			t.Errorf("[case %d] unexpected hash count: expected '%d' but got '%d'", i, c.Hashes, count)
		}

	}

}

func BenchmarkScan(b *testing.B) {

	var (
		StartPrefix = [3]byte{0x05, 0x31, 0x91}
		EndPrefix   = [3]byte{0x05, 0x31, 0x91}
	)

	od, err := NewOfflineDatabase(DatabaseFilename, UpdatedDatabaseFilename)
	if err != nil {
		b.Fatalf("unexpected error: %s", err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {

		var count, frequency int
		var hash [20]byte

		err := od.Scan(StartPrefix, EndPrefix, hash[:], func(freq uint16) bool {
			count++
			frequency += int(freq)
			return false
		})

		if err != nil {
			b.Fatalf("[case %d] unexpected error: %s", i, err)
		}

		if expected := 68; count != expected {
			b.Errorf("[case %d] unexpected hash count: expected '%d' but got '%d'", i, expected, count)
		}

		if expected := 272; frequency != expected {
			b.Errorf("[case %d] unexpected total leaks: expected '%d' but got '%d'", i, expected, frequency)
		}

	}

}

func TestLookup(t *testing.T) {

	cases := []struct {
		Start            [3]byte
		Location, Length int64
	}{
		{
			Start:    [3]byte{0x00, 0x00, 0x00},
			Location: 0x00,
			Length:   2755,
		},
		{
			Start:    [3]byte{0x05, 0x31, 0x91},
			Location: 0x137B4739,
			Length:   1292,
		},
	}

	od, err := NewOfflineDatabase(DatabaseFilename, UpdatedDatabaseFilename)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	for i, c := range cases {

		loc, length, err := od.lookup(c.Start)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}

		if loc != c.Location {
			t.Errorf("[case %d] unexpected location: expected '%x' but got '%x'\n", i, c.Location, loc)
		}

		if length != c.Length {
			t.Errorf("[case %d] unexpected length: expected [%d bytes] but got [%d bytes]\n", i, c.Length, length)
		}

	}

}

func BenchmarkHTTPPassword(b *testing.B) {

	// open the offline database
	od, err := NewOfflineDatabase(DatabaseFilename, UpdatedDatabaseFilename)
	if err != nil {
		panic(err)
	}
	defer od.Close()

	// start a dummy HTTP server
	s := httptest.NewServer(od)
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
		} else if n != 6 {
			b.Fatalf("unexpected response length: %d\n", n)
		}

		resp.Body.Close()

	}

}

func BenchmarkHTTPRange(b *testing.B) {

	// open the offline database
	od, err := NewOfflineDatabase(DatabaseFilename, UpdatedDatabaseFilename)
	if err != nil {
		panic(err)
	}
	defer od.Close()

	// start a dummy HTTP server
	s := httptest.NewServer(od)
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
		} else if n != 32982 {
			b.Fatalf("unexpected response length: %d\n", n)
		}

		resp.Body.Close()

	}

}
