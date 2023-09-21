package main

import (
	"flag"
	"net/http"

	"github.com/hm-edu/pwnedpass"
)

func main() {

	// parse flags
	var (
		dbFile        string
		updatedDbFile string
	)
	flag.StringVar(&dbFile, "database", pwnedpass.DatabaseFilename, "path to the database file")
	flag.StringVar(&updatedDbFile, "updated-database", pwnedpass.UpdatedDatabaseFilename, "path to the database file")
	flag.Parse()

	// open the offline database
	od, err := pwnedpass.NewOfflineDatabase(dbFile, updatedDbFile)
	if err != nil {
		panic(err)
	}
	defer od.Close()

	// start the http server
	http.ListenAndServe(":8889", od)

}
