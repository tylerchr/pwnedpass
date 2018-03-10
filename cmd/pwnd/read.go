package main

import (
	"flag"
	"net/http"

	"github.com/tylerchr/pwnedpass"
)

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

	// start the http server
	http.ListenAndServe(":8889", od)

}
