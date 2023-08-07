package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strconv"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// IndexSegmentSize is the exact size of the index segment in bytes.
const IndexSegmentSize = 256 << 16 << 3 // exactly 256^3 MB

// DatabaseFilename indicates the default location of the database file
// to be created.
var DatabaseFilename = "pwned-passwords.bin"

func main() {

	// choose a database filename
	dbFile := DatabaseFilename
	if len(os.Args) > 1 {
		dbFile = os.Args[1]
	}

	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.TimeKey = "timestamp"
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	config := zap.Config{
		Level:             zap.NewAtomicLevelAt(zap.InfoLevel),
		Development:       false,
		DisableCaller:     true,
		DisableStacktrace: false,
		Sampling:          nil,
		Encoding:          "json",
		EncoderConfig:     encoderCfg,
		OutputPaths: []string{
			"stderr",
		},
		ErrorOutputPaths: []string{
			"stderr",
		},
		InitialFields: map[string]interface{}{
			"pid": os.Getpid(),
		},
	}

	logger := zap.Must(config.Build())
	defer logger.Sync() // flushes buffer, if any
	sugar := logger.Sugar()
	// open data file
	df, err := os.Create(dbFile)
	if err != nil {
		panic(err)
	}
	defer df.Close()

	// wrap data file in a buffer for performance
	dff := bufio.NewWriterSize(df, 16<<20)
	defer dff.Flush()

	// prepare header and record buffers
	var hdr bytes.Buffer
	var record [22]byte

	var dataPointer uint64
	var currentHeader [3]byte

	// skip over the index segment space
	sugar.Infof("Reserving space for the index segment...")
	if _, err := df.Seek(IndexSegmentSize, io.SeekStart); err != nil {
		panic(err)
	}

	// write the data segment
	sugar.Infof("Writing data segment...")
	httpClient := &http.Client{}
	for i := int64(0); i < int64(math.Pow(16, 5)); i++ {
		sugar.Infof("Downloading range %05x...", i)
		req, err := http.NewRequest("GET", "https://api.pwnedpasswords.com/range/"+fmt.Sprintf("%05x", i), nil)
		if err != nil {
			sugar.Warnf("failed to send request: %s", err)
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			sugar.Warnf("failed to send request: %s", err)
		}
		defer resp.Body.Close()
		s := bufio.NewScanner(resp.Body)
		for s.Scan() {
			// read line, trimming right-hand whitespace
			line := bytes.TrimRight(s.Bytes(), " \r\n")
			line = []byte(fmt.Sprintf("%05x%s", i, line))
			// decode hash
			if _, err := hex.Decode(record[:20], line[:40]); err != nil {
				panic(err)
			}

			// parse count
			count, err := strconv.ParseInt(string(line[41:]), 10, 64)
			if err != nil {
				panic(err)
			}

			// write the header pointer out, if necessary
			if dataPointer == 0 || !bytes.Equal(currentHeader[:], record[0:3]) {
				copy(currentHeader[:], record[0:3])
				binary.Write(&hdr, binary.BigEndian, dataPointer)
			}

			// write back out
			binary.BigEndian.PutUint16(record[20:], uint16(count))
			dff.Write(record[3:]) // trim off the first three bytes to use as the index

			// increment index of next write
			dataPointer += (17 + 2) // length of written data

			if err := s.Err(); err != nil {
				panic(err)
			}
		}
		// make sure all data segment writes are through
		dff.Flush()
	}

	// assert that the header data is the expected size (exactly 256^3 MB)
	if hdr.Len() != IndexSegmentSize {
		panic(fmt.Errorf("unexpected amount of header data: %d bytes", hdr.Len()))
	}

	// seek back to the beginning of the file
	if _, err := df.Seek(0, io.SeekStart); err != nil {
		panic(err)
	}

	sugar.Infof("Writing index segment...")
	if _, err := io.Copy(dff, &hdr); err != nil {
		panic(err)
	}

	sugar.Infof("OK")

}
