package pwnedpass

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/exp/mmap"
)

const (
	// DatabaseFilename is the default path to the database.
	DatabaseFilename = "pwned-passwords.bin"

	// IndexSegmentSize is the exact size of the index segment in bytes.
	IndexSegmentSize = 256 << 16 << 3 // exactly 256^3 MB

	// DataSegmentOffset indicates the byte offset in the database where
	// the data segment begins.
	DataSegmentOffset = IndexSegmentSize
)

var (
	// FirstPrefix is the very first prefix in the dataset. It is intended
	// to be used as a parameter to Scan.
	FirstPrefix = [3]byte{0x00, 0x00, 0x00}

	// LastPrefix is the very last prefix in the dataset. It is intended
	// to be used as a parameter to Scan.
	LastPrefix = [3]byte{0xFF, 0xFF, 0xFF}

	// bigBufferPool is a pool of large-ish buffer objects available for reuse.
	bigBufferPool = &sync.Pool{New: func() interface{} {
		return make([]byte, 8<<10)
	}}
)

type (
	OfflineDatabase struct {
		database readCloserAt
	}

	// readCloserAt is an io.ReaderAt that can be Closed and whose
	// length can be obtained.
	//
	// Note that both *mmap.ReaderAt and *bytes.Reader implement this
	// interface.
	readCloserAt interface {
		io.ReaderAt
		io.Closer
		Len() int
	}
)

func NewOfflineDatabase(dbFile string) (*OfflineDatabase, error) {

	db, err := mmap.Open(dbFile)
	if err != nil {
		return nil, fmt.Errorf("error opening index: %s", err)
	}

	odb := &OfflineDatabase{
		database: db,
	}

	return odb, nil

}

// Close frees resources associated with the database.
func (od *OfflineDatabase) Close() error {
	return od.database.Close()
}

// Pwned checks whether the given hash is included in the Pwned Passwords database.
func (od *OfflineDatabase) Pwned(hash [20]byte) (frequency int, err error) {

	var prefix [3]byte
	copy(prefix[0:3], hash[0:3])

	var pwnedHash [20]byte
	err = od.Scan(prefix, prefix, pwnedHash[:], func(freq int64) bool {
		if pwnedHash == hash {
			frequency = int(freq)
			return true
		}
		return false
	})

	return frequency, err

}

// Scan iterates through all hashes between startPrefix and endPrefix (inclusive).
// Iteration begins at the first hash with a prefix of startPrefix and continues
// until one of these conditions is met:
//
//     1) the last hash with a prefix of endPrefix has been reached,
//     2) the callback returns "true" to indicate a stop is requested,
//  or 3) the end of the hash database is reached.
func (od *OfflineDatabase) Scan(startPrefix, endPrefix [3]byte, hash []byte, cb func(frequency int64) bool) error {

	if bytes.Compare(startPrefix[:], endPrefix[:]) == 1 {
		return errors.New("invalid range: startPrefix > endPrefix")
	}

	buffer := bigBufferPool.Get().([]byte)

	var shortPrefix [3]byte = startPrefix
	var fullPrefix [4]byte
	copy(fullPrefix[1:4], startPrefix[0:3])

	copy(hash[0:3], startPrefix[0:3])

	var currentPrefix uint32 = binary.BigEndian.Uint32(fullPrefix[:])

	for {

		// look up location in the index
		start, length, err := od.lookup(shortPrefix)
		if err != nil {
			return err
		}

		// read from the data file
		if _, err := od.database.ReadAt(buffer[0:length], DataSegmentOffset+start); err != nil {
			return err
		}

		for offset := int64(0); offset < length; offset += 19 {

			copy(hash[3:20], buffer[offset:offset+17])
			frequency := int64(binary.BigEndian.Uint16(buffer[offset+17 : offset+19]))

			if stop := cb(frequency); stop {
				return nil
			}

		}

		// stop if we've reached the end prefix, inclusive
		if shortPrefix == endPrefix {
			break
		}

		// advance the current prefix pointer
		currentPrefix++
		binary.BigEndian.PutUint32(fullPrefix[0:4], currentPrefix)
		copy(shortPrefix[0:3], fullPrefix[1:4])
		copy(hash[0:3], fullPrefix[1:4])

		// stop if we're reaching beyond the end
		if currentPrefix > 256<<16 {
			break
		}

	}

	return nil
}

// lookup returns the location of a block of data in the index
func (od *OfflineDatabase) lookup(start [3]byte) (location, length int64, err error) {

	// get a small buffer to reuse for various things here
	var buffer [16]byte

	// get location as integer
	copy(buffer[1:4], start[:])
	prefixIndex := binary.BigEndian.Uint32(buffer[0:4]) // number between 0x00000000 and 0x00FFFFFF

	var loc, dataLen int64

	switch start {

	// If we're looking up 0x00FFFFFF there won't be a next one to check, so don't try.
	case [3]byte{0xFF, 0xFF, 0xFF}:

		// read the required index
		if _, err := od.database.ReadAt(buffer[0:8], int64(prefixIndex)*8); err != nil {
			return 0, 0, err
		}

		// look up locations and calculate length
		loc = int64(binary.BigEndian.Uint64(buffer[0:8]))
		dataLen = int64(od.database.Len()-IndexSegmentSize) - loc

	default:

		// read the required index, and the next one (to calculate length)
		if _, err := od.database.ReadAt(buffer[0:16], int64(prefixIndex)*8); err != nil {
			return 0, 0, err
		}

		// look up locations and calculate length
		var nextLoc int64
		loc, nextLoc = int64(binary.BigEndian.Uint64(buffer[0:8])), int64(binary.BigEndian.Uint64(buffer[8:16]))
		dataLen = nextLoc - loc

	}

	return loc, dataLen, nil

}
