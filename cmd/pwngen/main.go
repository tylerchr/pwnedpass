package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strconv"
	"strings"
)

func main() {

	go http.ListenAndServe(":8888", nil)

	// read from the input stream
	rr, err := gzip.NewReader(os.Stdin)
	if err != nil {
		panic(err)
	}
	defer rr.Close()

	// open data file
	df, err := os.Create("pwned-passwords-data.bin")
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

	s := bufio.NewScanner(rr)
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

	fmt.Printf("Dumping header file: [%d bytes]\n", hdr.Len())

	// open header file
	hf, err := os.Create("pwned-passwords-index.bin")
	if err != nil {
		panic(err)
	}
	defer hf.Close()

	// dump header file
	if _, err := hdr.WriteTo(hf); err != nil {
		panic(err)
	}

}
