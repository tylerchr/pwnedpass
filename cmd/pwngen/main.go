package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// IndexSegmentSize is the exact size of the index segment in bytes.
const IndexSegmentSize = 256 << 16 << 3 // exactly 256^3 MB

func main() {

	// open data file
	df, err := os.Create("pwned-passwords.bin")
	if err != nil {
		panic(err)
	}
	defer df.Close()

	// wrap data file in a buffer for performance
	dff := bufio.NewWriterSize(df, 16<<20)
	defer dff.Flush()

	// prepare header buffer
	var hdr bytes.Buffer

	var dataPointer uint64
	var currentHeader [3]byte

	// open a stream of zeros
	zero, err := os.Open("/dev/zero")
	if err != nil {
		panic(err)
	}
	defer zero.Close()

	// write zeros in the index segment space
	fmt.Println("Reserving space for the index segment...")
	if _, err := io.CopyN(dff, zero, IndexSegmentSize); err != nil {
		panic(err)
	}

	// write the data segment
	fmt.Println("Writing data segment...")
	s := bufio.NewScanner(os.Stdin)
	for s.Scan() {

		// read line, trimming right-hand whitespace
		line := strings.TrimRight(s.Text(), string([]byte{0x20}))

		// decode hash
		hh, err := hex.DecodeString(line[0:40])
		if err != nil {
			panic(err)
		}

		// parse count
		count, err := strconv.ParseInt(line[41:], 10, 64)
		if err != nil {
			panic(err)
		}

		// write the header pointer out, if necessary
		if dataPointer == 0 || !bytes.Equal(currentHeader[:], hh[0:3]) {
			copy(currentHeader[:], hh[0:3])
			binary.Write(&hdr, binary.BigEndian, dataPointer)
		}

		// write back out
		binary.Write(dff, binary.BigEndian, hh[3:]) // trim off the first three bytes to use as the index
		binary.Write(dff, binary.BigEndian, uint16(count))

		// increment index of next write
		dataPointer += (17 + 2) // length of written data
	}

	if err := s.Err(); err != nil {
		panic(err)
	}

	// make sure all data segment writes are through
	dff.Flush()

	// assert that the header data is the expected size (exactly 256^3 MB)
	if hdr.Len() != IndexSegmentSize {
		panic(fmt.Errorf("unexpected amount of header data: %d bytes", hdr.Len()))
	}

	// seek back to the beginning of the file
	if _, err := df.Seek(0, io.SeekStart); err != nil {
		panic(err)
	}

	fmt.Println("Writing index segment...")
	if _, err := io.Copy(dff, &hdr); err != nil {
		panic(err)
	}

	fmt.Println("OK")

}
