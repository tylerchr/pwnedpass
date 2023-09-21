package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/robfig/cron/v3"
	concurrently "github.com/tejzpr/ordered-concurrently/v3"
)

// IndexSegmentSize is the exact size of the index segment in bytes.
const IndexSegmentSize = 256 << 16 << 3 // exactly 256^3 MB

// DatabaseFilename indicates the default location of the database file
// to be created.
var DatabaseFilename = "updated-pwned-passwords.bin"
var LockFileName = "pwned-passwords.lock"

type loadWorker struct {
	sugar *zap.SugaredLogger
	index int64
}

type response struct {
	Index int64
	Body  []byte
}

// The work that needs to be performed
// The input type should implement the WorkFunction interface
func (w loadWorker) Run(ctx context.Context) interface{} {
	os.Create(LockFileName)
	var body []byte
	for i := 0; i < 3; i++ {
		httpClient := &http.Client{}
		req, err := http.NewRequest("GET", "https://api.pwnedpasswords.com/range/"+fmt.Sprintf("%05x", w.index), nil)
		if err != nil {
			w.sugar.Warnf("failed to send request: %s", err)
			continue
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			w.sugar.Warnf("failed to send request: %s", err)
			continue
		}
		defer resp.Body.Close()

		body, err = io.ReadAll(resp.Body)
		if err != nil {
			w.sugar.Warnf("failed to read response body: %s", err)
			continue
		}
		break
	}
	if len(body) == 0 {
		w.sugar.Fatal("failed to load index %d", w.index)
	}
	return response{Index: w.index, Body: body}
}
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

	Run(sugar, dbFile)
	cron := cron.New()
	cron.AddFunc("@daily", func() {
		Run(sugar, dbFile)
	})
	cron.Start()
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
	<-done
	cron.Stop()
}

func Run(logger *zap.SugaredLogger, dbFile string) {
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
	logger.Infof("Reserving space for the index segment...")
	if _, err := df.Seek(IndexSegmentSize, io.SeekStart); err != nil {
		logger.Panicf("failed to seek to index segment: %s", err)
	}

	// write the data segment
	logger.Infof("Writing data segment...")
	inputChan := make(chan concurrently.WorkFunction)
	ctx := context.Background()
	output := concurrently.Process(ctx, inputChan, &concurrently.Options{PoolSize: 30, OutChannelBuffer: 30})
	go func() {
		for i := int64(0); i < int64(math.Pow(16, 5)); i++ {
			inputChan <- loadWorker{logger, i}
		}
		close(inputChan)
	}()
	for out := range output {

		resp := out.Value.(response)
		if resp.Index%100 == 0 {
			logger.Infof("Handling segment %d", resp.Index)
		}
		scanner := bufio.NewScanner(strings.NewReader(string(resp.Body)))
		for scanner.Scan() {
			// read line, trimming right-hand whitespace
			line := strings.TrimRight(scanner.Text(), " \r\n")

			data := []byte(fmt.Sprintf("%05x%s", resp.Index, line))
			// decode hash
			if _, err := hex.Decode(record[:20], data[:40]); err != nil {
				logger.Panicf("failed to decode hash: %s", err)
			}

			// parse count
			count, err := strconv.ParseInt(string(data[41:]), 10, 64)
			if err != nil {
				logger.Panicf("failed to parse count: %s", err)
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
		}

		// make sure all data segment writes are through
		dff.Flush()
	}

	// assert that the header data is the expected size (exactly 256^3 MB)
	if hdr.Len() != IndexSegmentSize {
		logger.Panicf("unexpected header size: expected '%d' but got '%d'", IndexSegmentSize, hdr.Len())
	}

	// seek back to the beginning of the file
	if _, err := df.Seek(0, io.SeekStart); err != nil {
		logger.Panicf("failed to seek to beginning of file: %s", err)
	}

	logger.Infof("Writing index segment...")
	if _, err := io.Copy(dff, &hdr); err != nil {
		logger.Panicf("failed to write index segment: %s", err)
	}

	logger.Infof("OK")
	os.Remove(LockFileName)
}
