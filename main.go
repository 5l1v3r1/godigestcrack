package main

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

func main() {
	fmt.Println("godigestcrack gogogo")
	workerPtr := flag.Int("workers", 4, "number of threads to crack with")
	usrnamePtr := flag.String("usr", "", "Username")
	realmPtr := flag.String("realm", "", "Realm to auth against")
	noncePtr := flag.String("nonce", "", "Nonce")
	respPtr := flag.String("resp", "", "Target response value (should be md5)")
	uriPtr := flag.String("uri", "/", "Path to use")
	ncPtr := flag.String("nc", "00000001", "NC or NonceCounter")
	qopPtr := flag.String("qop", "auth", "qop")
	methPtr := flag.String("method", "GET", "Method")
	cnoncePtr := flag.String("cnonce", "", "CNONCE value")
	boolPtr := flag.Bool("stdin", true, "use stdin mode (Default)")
	wordlistPtr := flag.String("words", "", "Wordlist to use when in wordlist mode")

	flag.Parse()
	//precompute ha2 for speed?
	ha2 := getHash(*methPtr + ":" + *uriPtr)

	//set up a ticker to show output every 2 seconds
	ticker := time.NewTicker(time.Millisecond * 2000).C
	var hashcount uint64 = 0               //total attempts at cracking password
	var sekret = *respPtr                  //the thing we are trying to get
	passwordList := make(chan string, 500) //arbitrarily chose size of this - happy to pick a better number but this seems fine for now
	win := make(chan string)               // Not sure this is the best way of doing parallel (wait groups might work better?), agian, whatever

	//display output to identify any silly input mistakes user may have made
	fmt.Printf("Attempting to crack auth header using the following params (there should be no quotes in these):\n")
	fmt.Printf("Threads:%d\nUsername:%s\nRealm:%s\nNonce:%s\nURI:%s\nCNonce:%s\nNC:%s\nQOP:%s\nMethod:%s\nResp:%s\n",
		*workerPtr, *usrnamePtr, *realmPtr, *noncePtr, *uriPtr, *cnoncePtr, *ncPtr, *qopPtr, *methPtr, *respPtr)

	//start the input/creator goroutine
	if len(*wordlistPtr) > 0 {
		*boolPtr = false
	}
	go fillWordlist(passwordList, *boolPtr, *wordlistPtr)

	//start the consumer goroutines - could probably make this automatically work out how many workers are optimal based on current hashing speed
	for x := 0; x < *workerPtr; x++ {
		go crackPassword(passwordList, win, sekret, &hashcount, *cnoncePtr, ha2, *noncePtr, *ncPtr, *realmPtr, *usrnamePtr, *qopPtr)
	}

	//keep an eye on our workers, and display output
	seconds := uint64(0)
	lastCount := uint64(0)
	printCount := uint64(0)
	for {
		select {
		case hacked := <-win: //this should exit the program if we win
			fmt.Println(hacked)
			return
		case <-ticker:
			seconds += 2
			printCount = (hashcount - lastCount) / 2
			fmt.Printf("\r                                                            \r"+
				"%fmh/s, %d seconds, %d in total",
				float32(printCount)/1000000, seconds, hashcount)
			lastCount = hashcount
		}
	}
}

func fillWordlist(passwords chan<- string, stdin bool, wordlist string) {
	if stdin {
		fmt.Println("Using Stdin...")
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			passwords <- strings.Trim(scanner.Text(), "\n ")
		}
		return
	}

	fmt.Println("Using wordlist: " + wordlist)
	file, err := os.Open(wordlist)
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		passwords <- scanner.Text()
	}
	return

}

func getAuthHash(password string, cnonce string, ha2 string, nonce string, nc string, realm string, user string, qop string) string {
	resp := getHash(getHash(user+":"+realm+":"+password) + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2)
	return resp
}

func getHash(password string) string {
	//creating a new md5 object every hash computation seems inefficient, there is probably a better way of doing this
	hasher := md5.New()
	hasher.Write([]byte(password))
	return hex.EncodeToString(hasher.Sum(nil))
}

func crackPassword(passwords <-chan string, win chan<- string, target string, count *uint64, cnonce string, ha2 string, nonce string, nc string, realm string, user string, qop string) {
	//goroutine thingo, reads from the passwords channel, and compares the output to the target output
	for pass := range passwords {
		v := getAuthHash(pass, cnonce, ha2, nonce, nc, realm, user, qop) //Could be optimized to avoid string casting, and simply compare slices per-gouroutine
		if v == target {
			win <- pass
		}
		atomic.AddUint64(count, 1) //neat way of performance counting that apparently doesn't impact performance too much
	}
}
