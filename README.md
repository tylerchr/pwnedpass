# `pwnedpass` [![GoDoc](https://godoc.org/github.com/tylerchr/pwnedpass?status.svg)](https://godoc.org/github.com/tylerchr/pwnedpass)

Package `pwnedpass` is a Go package for querying a local instance of Troy Hunt's Pwned Passwords database. It also implements an http.Handler that reproduces the online Pwned Passwords HTTP API.

For a complete HTTP server built on top of this package, see sub-package [pwnd](https://github.com/tylerchr/pwnedpass/tree/master/cmd/pwnd).

## Usage

The `pwnedpass` package exports two primary functions, `Pwned` and `Scan`, which loosely mirror the official [password](https://haveibeenpwned.com/API/v2#SearchingPwnedPasswordsByPassword) and [range](https://haveibeenpwned.com/API/v2#SearchingPwnedPasswordsByRange) APIs respectively.

Querying a local Pwned Passwords database requires a local copy of the Pwned Passwords database; see "Database File" below for details on how to generate this.

```go
od, _ := pwnedpass.NewOfflineDatabase("pwned-passwords.bin") // see "Database File" below
```

### Pwned Password

The `Pwned` method indicates whether the given password appears in the dataset by returning its number of occurrences. This number will be zero for unpwned passwords.

```go
// search by password
freq, _ := od.Pwned(sha1.Sum([]byte("P@ssword")))
fmt.Println(freq)

// 5728

// Compare with https://api.pwnedpasswords.com/pwnedpassword/P@ssword
```

### Range Scan

The `Scan` method iterates efficiently through the range of hashes included between `startPrefix` and `endPrefix` inclusive. In other words, iteration begins with the first hash to begin with `startPrefix` and continues through and including the last hash that begins with `endPrefix`. Observe that if the same value is provided for both the `startPrefix` and `endPrefix` arguments, then `Scan` iterates only through hashes with exactly that prefix.

Note that these prefixes are 3-byte prefixes (6 hex digits), as opposed to the 2.5-byte (5 hex digit) prefixes accepted by the online Range API. Users wishing to emulate the 5-digit semantics should append a `0` to the `startPrefix` and a `F` to the `endPrefix`, as in this example.

```go
// search by range
var (
	startPrefix = [3]byte{0x21, 0xBD, 0x10}
	endPrefix   = [3]byte{0x21, 0xBD, 0x1F}
)

var hash [20]byte
od.Scan(startPrefix, endPrefix, hash[:], func(freq uint16) bool {
	fmt.Printf("%x:%d\n", hash, freq)
})

// 21BD10018A45C4D1DEF81644B54AB7F969B88D65:1
// 21BD100D4F6E8FA6EECAD2A3AA415EEC418D38EC:2
// 21BD1011053FD0102E94D6AE2F8B83D76FAF94F6:1
// ...
// 21BD1FE867A959E87530DED79F9709D4E7BDCD5D:2
// 21BD1FE92D1CF40DCB5C9BAE484B1CABCC9112E1:6
// 21BD1FF185A609DEA5042A77EF4238E4BD7C5E72:3

// Compare with https://api.pwnedpasswords.com/range/21BD1
```

## Database File

Using the `pwnedpass` package depends on having a Pwned Passwords database file. To minimize storage and memory requirements, this package uses a binary encoded variation on the stock [Pwned Passwords database file](https://haveibeenpwned.com/Passwords).

The file format is extremely simple and is documented below. Additionally, this repository contains a utility (see sub-command [pwngen](https://github.com/tylerchr/pwnedpass/tree/master/cmd/pwngen)) that produces the binary encoding from the [stock ASCII version](https://haveibeenpwned.com/Passwords).

```bash
$ go install github.com/tylerchr/pwnedpass/cmd/pwngen
$ 7z e -so ./pwned-passwords-2.0.txt.7z pwned-passwords-ordered-2.0.txt | pwngen pwned-passwords.bin
Reserving space for the index segment...
Writing data segment...
Writing index segment...
OK
```

This process takes approximately 21:30 on my 2012 iMac, and results in a 9GB `pwned-passwords.bin` file. Note that you must use the _ordered_ database file for correct results here.

| File                        | SHA-1 of stock 7-Zip file                | SHA-1 of binary file                     |
| --------------------------- | ---------------------------------------- | ---------------------------------------- |
| Version 2 (ordered by hash) | 87437926c6293d034a259a2b86a2d077e7fd5a63 | 9ea32216da1ab11ac2c9a29e19c33f1c2e6ecd1a |

### File Format

The binary file format consists of two concatenated segments: an index segment and a data segment. The data segment contains every hash in the dataset paired with a 16-bit expression of its appearance frequency, while the index segment contains every 3-byte prefix paired with a pointer into the data segment of the first hash with that prefix.

Hashes exist in the dataset for all 16,777,216 3-byte prefixes (`256^3`), and since byte offsets are expressed as big-endian uint64 values the total size of the index segment is always exactly `16,777,216 * 8 bytes = 128 MB`.

```
+-----------------+-----------------+-----------------+-- ~ --+-----------------+
| ptr to 0x000000 | ptr to 0x000001 | ptr to 0x000002 |  ...  | ptr to 0xFFFFFF |
+-----------------+-----------------+-----------------+-- ~ --+-----------------+
      8 bytes           8 bytes           8 bytes                   8 bytes
```

The data segment contains each hash in sorted order, paired with a 16-bit big-endian representation of its frequency. To save space, the first 3 bytes of each hash are omitted as they can be recovered from the index as discussed above. Combined with the frequency value, this means that each hash occupies `17 + 2 = 19 bytes`.

```
+--------------------------------------+---+--------------------------------------+---+-- ~ --
| 0x005AD76BD555C1D6D771DE417A4B87E4B4 | 3 | 0x00A8DAE4228F821FB418F59826079BF368 | 2 |  ...  
+--------------------------------------+---+--------------------------------------+---+-- ~ --
                 17 bytes                ^                  17 bytes                ^
                                         |                                          |
                                      2 bytes                                    2 bytes
```

This sequence repeats for all hashes in the dataset, which as of this moment is 501,636,842. The observant reader might notice at this point that all these numbers line up:

```
$ ls -la pwned-passwords.bin
-rw-r--r--   1 tylerchr  staff   9665317726 Mar  8 16:56 pwned-passwords.bin

# (256^3 * 8) + (501,636,842 * (17 + 2)) = 9665317726 bytes
# (256^3 * 8) + (501,636,842 * 19        = 9665317726 bytes
# 134,217,728 + 9,531,099,998            = 9665317726 bytes
```

For more details on the design choices of this file format, see [the associated blog post]().