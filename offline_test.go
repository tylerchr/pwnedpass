package pwnedpass

import (
	"crypto/sha1"
	"testing"
)

func TestOfflineDatabase_Pwned(t *testing.T) {

	cases := []struct {
		Password  string
		Frequency int
	}{
		{
			Password:  "P@ssword",
			Frequency: 5728,
		},
		{
			Password:  "775f96123edda7b3bc918bb155757d58df98246e",
			Frequency: 0,
		},
	}

	od, err := NewOfflineDatabase(DatabaseFilename)
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

func BenchmarkOfflineDatabase_Pwned(b *testing.B) {

	od, err := NewOfflineDatabase(DatabaseFilename)
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

func TestOfflineDatabase_Scan(t *testing.T) {

	cases := []struct {
		StartPrefix, EndPrefix [3]byte
		UseCutoffPrefix        bool
		CutoffPrefix           [3]byte // the prefix at which to terminate execution via the callback
		Hashes                 int
	}{
		{
			StartPrefix: [3]byte{0x00, 0x00, 0x00},
			EndPrefix:   [3]byte{0x00, 0x00, 0x00},
			Hashes:      73,
		},
		{
			StartPrefix: [3]byte{0x05, 0x31, 0x91},
			EndPrefix:   [3]byte{0x05, 0x31, 0x91},
			Hashes:      43,
		},
		{
			StartPrefix: [3]byte{0x05, 0x31, 0x91},
			EndPrefix:   [3]byte{0x05, 0x31, 0x92},
			Hashes:      70,
		},
		{
			StartPrefix: [3]byte{0xFF, 0xFF, 0xFF},
			EndPrefix:   [3]byte{0xFF, 0xFF, 0xFF},
			Hashes:      30,
		},
	}

	od, err := NewOfflineDatabase(DatabaseFilename)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	for i, c := range cases {

		var count int

		err = od.Scan(c.StartPrefix, c.EndPrefix, func(hash [20]byte, freq uint16) bool {
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

func TestOfflineDatabase_Lookup(t *testing.T) {

	cases := []struct {
		Start            [3]byte
		Location, Length int64
	}{
		{
			Start:    [3]byte{0x00, 0x00, 0x00},
			Location: 0x00,
			Length:   1387,
		},
		{
			Start:    [3]byte{0x05, 0x31, 0x91},
			Location: 0x0B88C28A,
			Length:   817,
		},
	}

	od, err := NewOfflineDatabase(DatabaseFilename)
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
