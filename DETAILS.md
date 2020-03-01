# Local Pwned Passwords lookups in 50 μs or less

_10 March 2018_

A lot has been made of Troy Hunt’s new [Pwned Passwords V2](https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/) API. It got a lot of well-earned attention after it was announced, especially for its [privacy-preserving Range API](https://haveibeenpwned.com/API/v2#SearchingPwnedPasswordsByRange), and even two weeks later it’s still a regular feature on my Twitter feed.

The only thing better than a free, useful API is a fast API. Troy must agree, as he followed up his original post with "[I Wanna Go Fast](https://www.troyhunt.com/i-wanna-go-fast-why-searching-through-500m-pwned-passwords-is-so-quick/)," but the Hacker News crowd [didn’t seem all that enthused](https://news.ycombinator.com/item?id=16472089). They seemed to think that Troy’s design was leaving all sorts of performance on the table. I got curious and started trying to figure out exactly how fast this API could possibly be.

I don’t know what the exact lower bound is, but I got an implementation down to 50 microseconds or so. I thought that was pretty good.

For the impatient, that implementation is available as a Go library ([GoDoc](https://godoc.org/github.com/tylerchr/pwnedpass), [GitHub](https://github.com/tylerchr/pwnedpass)) if you want to dive right in. The rest of this post explains its design and performance properties.

## Design

Networks are slow, so a maximum performance API is going to have to do away with that. Luckily, Troy makes available his [raw data](https://haveibeenpwned.com/Passwords) in the form of a text file with 501,636,842 password hashes and counts. Because querying sorted data is faster than unsorted data, I started with the `pwned-passwords-ordered-2.0.txt.7z` file.

The uncompressed data comes out to around 30GB, which is an annoying quantity to work with locally. Fortunately, there are some easy optimization opportunities for us to exploit. In order to cut down the disk/memory requirements, I used these properties to implement a custom binary file format:

- Each line of the ordered file contains a hex-encoded SHA1 hash, which comes out to 40 bytes. By storing the hashes in binary form, we can cut this in half to 20 bytes per hash.
- Since SHA1 is relatively [uniform](https://en.wikipedia.org/wiki/Hash_function#Uniformity) hash function, the hashes are spread out pretty evenly across the total space. With 501 million passwords, this means that many of them share common prefixes. We can save a few more bytes per hash by factoring out repetitive prefixes and doing something else to track them.
- Each hash is paired with a count to indicate how frequently that hash has appeared in breaches. This value is ASCII-encoded in the original dataset, so the largest value that can be represented in, say, two bytes is 99. Unfortunately there are some really bad passwords out there that have been compromised many more times than that, so I chose to store the number as a raw uint16 instead for a maximum value of 65,535. I figure any password compromised more times than that is totally hopeless, so storing a greater number doesn’t buy much.

After some experimenting I wound up with the following binary file format. Some nice properties of this format are its simplicity, compact size, and efficiency in lookups.

The database file consists of two concatenated segments: an *index segment* and a *data segment*. For every hash in the dataset, the data segment contains the hash immediately followed by a 16-bit expression of its appearance frequency; the index segment contains every 3-byte prefix paired with a pointer into the data segment of the first hash with that prefix. Indices appear in order in the index segment, and hashes appear in sorted order in the data segment.

```
        Index Segment

+-----------------+-----------------+-----------------+-- ~ --+-----------------+-----
| ptr to 0x000000 | ptr to 0x000001 | ptr to 0x000002 |  ...  | ptr to 0xFFFFFF | ...
+-----------------+-----------------+-----------------+-- ~ --+-----------------+-----
      8 bytes           8 bytes           8 bytes                   8 bytes



        Data Segment

-----+--------------------------------------+---+--------------------------------------+---+-- ~ --+
 ... | 0x005AD76BD555C1D6D771DE417A4B87E4B4 | 3 | 0x00A8DAE4228F821FB418F59826079BF368 | 2 |  ...  |
-----+--------------------------------------+---+--------------------------------------+---+-- ~ --+
                      17 bytes                ^                  17 bytes                ^
                                              |                                          |
                                           2 bytes                                    2 bytes
```

For a sorted data set like this one, choosing an index size is a balancing act between granularity and index size. The index should be small enough to be reasonably accessible, but granular enough to provide a reasonably close approximation for the data being searched.

Note that hashes in the data segment are only 17 bytes rather than 20 because I'm not including the first three bytes (they appear in the index already, and can be re-derived quickly enough). They're very repetetive, and omitting them saves `501,636,842 * 3 = 1,504,910,526 = 1.5 GB`. I chose to index on the first 3 bytes of each hash, mostly via deduction from a few viable-sounding sizes:

- **2 bytes (512KB, 7654-hash ea.)**: A two-byte prefix makes for a very small index but isn't very granular and means that the data segment lookup has to search many thousands of hashes that begin that prefix to identify the target one. This could be done in `log(N)` time but that's still 13 reads on average.
- **2.5 bytes (8MB, 478-hash ea.)**: These numbers look pretty good, and this is what the online Range API uses (five hex characters comes out to 2.5 bytes). But to keep things simple and avoid bit shifting, I elected to disqualify partial-byte index sizes.
- **3 bytes (128MB, 30-hash ea.)**: A three-byte prefix gives an index that is acceptable in size and there are only about three dozen hashes per prefix. That's pretty reasonable on both counts.
- **4 bytes (32GB, 0.12-hash ea.)**: A four-byte prefix yields more index pointers than there are hashes in the dataset by a factor of 8.5 and would weigh in at many gigabytes. In my book that's a failing grade for both granularity and index size.

For more details on the file format, see the [project README](https://github.com/tylerchr/pwnedpass/#file-format) on GitHub.

## Performance
I wrote a Go program to convert Troy’s text file to this binary encoding, and then a library for querying it as well. All together, it comes out to just [a few hundred lines of code](https://github.com/tylerchr/pwnedpass/blob/master/offline.go).

One convenience of fitting all those hashes in 9GB is that there’s a good chance it’ll all fit in memory. But since I didn’t want to depend on that (and incur rather high startup latency copying it into RAM), my implementation memory-maps the file from disk. This lets the kernel manage what parts are in memory without having to reserve all 9GB up front.

- Latency of an unmapped hash (800 usec on my iMac)
- Latency of a mapped hash (30 usec)
- Latency of a hot hash (3 usec)

Troy’s original is an HTTP API and what I’ve described is a library, so it’s apples and oranges so far. To achieve a more fair comparison I wrote a simple HTTP wrapper around my library implementation to compare more directly.

To obtain measurements in milliseconds, I used this highly scientific bash command on my iMac to obtain the average latency across 50 requests:

```bash
for i in $(seq 1 50); do
   curl -w "%{time_total}\n" -o /dev/null -s https://127.0.0.1:4443/range/EC7D0;
done | awk '{sum+=$1} END {print sum / 50 * 1000}'
```

Queries over HTTP take much longer than the library equivalents, but still in the low milliseconds. Troy’s API can answer my queries in around 70ms, which is more a reflection of Cloudflare’s network than Troy’s actual implementation (without the Cloudflare network in between, I’m sure querying Troy’s Azure server is quite fast too).

## Prior Iterations

I tried several other ideas to try to glean more performance, like using a `sync.Pool` of small buffers and implementing a zero-allocation version. These versions both didn't increase performance appreciably, and required pretty deep changes that made the code harder to understand.

Another unpromising avenue was swapping out the Go stdlib's `http.Handler` for `fasthttp`, which advertises as being significantly more efficient. The port was very straightforward, but benchmarks didn't show much significant improvement. Honestly, I suspect this was due to a problem with my methodology, and I didn't expend much effort trying to understand this (I was put off by the fact that [no](https://httpd.apache.org/docs/2.4/programs/ab.html) [common](https://github.com/JoeDog/siege) [benchmark](https://github.com/tsenart/vegeta) tools seem to give sub-millisecond results).

An early version of the library's `Scan` function actually returned the entire block from the data segment matching a given prefix as a byte array. This was extremely fast (lookups were on the order of 15 usec) but it was a terrible API because it left the caller responsible to parse and iterate through the hashes. In the end I decided to sacrifice a small amount of performance in favor of a nicer API.

## Future Work

If I'm being honest, I've satisfied my curiosity at this point and don't intend to delve any deeper. But someone whose thirst isn't yet quenched might explore one of these topics:

- **Concurrency**: How well does performance scale with simultaneous request volume? In theory things should continue to work, but beyond a quick `ab -n 10000 -c 50` run I didn't explore this.
- **Sharding**: What happens when Troy releases another 500M hashes, and the next 500M after that? Perhaps it's cheaper to run multiple nodes with 4GB of memory than one node with 16GB. One could divide the hashes onto multiple machines to distribute the query load and better handle more volume. Distributing hashes evenly would be trivial due to SHA1's uniformity.
- **Memory Efficiency**: I'm particularly curious whether it's possible to reduce the size of the database any further. SHA1 output is pretty random-looking so I didn't expect compression to be a promising avenue, but I didn't explore that. Someone with an information theory background might be able to provide a lower bound.