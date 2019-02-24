package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/boltdb/bolt"
	"github.com/gorilla/mux"
	"github.com/urfave/negroni"
)

const link = "https://check.torproject.org/exit-addresses"

var layout = "2006-01-02 15:04:05"
var db *bolt.DB

type Node struct {
	Hash          string
	Published     time.Time
	LastStatus    time.Time
	ExitAddresses []*Address
}

type Address struct {
	IsRange   bool
	Ip        string
	Published time.Time
}

type sortByteArrays [][]byte

func (b sortByteArrays) Swap(i, j int) {
	b[j], b[i] = b[i], b[j]
}

func SortByteArrays(src [][]byte) [][]byte {
	sorted := sortByteArrays(src)
	return sorted
}

func main() {
	var err error
	db, err = bolt.Open("toro.db", 0600, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	go runTrack()
	router := mux.NewRouter()
	router.HandleFunc("/", IndexHandler).Methods("GET")
	router.HandleFunc("/compat/minutes/{minutes:[0-9]+}", CompatHandler).Methods("GET")
	router.HandleFunc("/nginx/minutes/{minutes:[0-9]+}", NginxHandler).Methods("GET")
	router.HandleFunc("/iptables/minutes/{minutes:[0-9]+}", IptablesHandler).Methods("GET")
	router.HandleFunc("/paloalto/minutes/{minutes:[0-9]+}", PaloAltoHandler).Methods("GET")
	router.HandleFunc("/powershell/minutes/{minutes:[0-9]+}/firewall.ps1", PowershellHandler).Methods("GET")

	n := negroni.New()
	n.Use(negroni.NewRecovery())
	n.Use(negroni.NewLogger())
	n.UseHandler(router)

	log.Fatal(http.ListenAndServe(":3005", n))
}

func runTrack() {
	track()
	tick := time.Tick(5 * time.Minute)
	// Keep trying until we're timed out or got a result or got an error
	for {
		select {
		// Got a timeout! fail with a timeout error
		case <-tick:
			err := track()
			if err != nil {
				log.Println(err)
			}
		}
	}
}

func track() error {
	var currentNode *Node
	var ips []net.IP
	req, err := http.NewRequest("GET", link, nil)
	if err != nil {
		return err
	}

	c := http.DefaultClient
	c.Timeout = 15 * time.Second
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	nodes := make(map[string]*Node)
	regEn := regexp.MustCompile("ExitNode ")
	regP := regexp.MustCompile("Published ")
	regLS := regexp.MustCompile("LastStatus ")
	regEA := regexp.MustCompile("ExitAddress ")
	regIP := regexp.MustCompile("\\d+\\.\\d+\\.\\d+\\.\\d+")

	scanner := bufio.NewScanner(resp.Body)

	for scanner.Scan() {
		st := scanner.Text()
		// parse exit node hash
		if regEn.MatchString(st) {
			s := strings.Replace(st, "ExitNode ", "", -1)
			currentNode = &Node{
				Hash: s,
			}
			nodes[s] = currentNode
		} else if regP.MatchString(st) {
			s := strings.Replace(st, "Published ", "", -1)
			t, err := time.Parse(layout, s)
			if err != nil {
				return err
			}
			currentNode.Published = t
		} else if regLS.MatchString(st) {
			s := strings.Replace(st, "LastStatus ", "", -1)
			t, err := time.Parse(layout, s)
			if err != nil {
				return err
			}
			currentNode.LastStatus = t
		} else if regEA.MatchString(st) {
			s := strings.Replace(st, "ExitAddress ", "", -1)
			ip := regIP.FindString(s)
			d := strings.Replace(s, ip+" ", "", -1)
			t, err := time.Parse(layout, d)
			if err != nil {
				return err
			}

			a := &Address{
				Ip:        ip,
				Published: t,
			}

			pipd := net.ParseIP(ip)
			ipd := net.IP.To4(pipd)
			ips = append(ips, ipd)

			currentNode.ExitAddresses = append(currentNode.ExitAddresses, a)
		}

		err = db.Update(func(tx *bolt.Tx) error {
			b, err := tx.CreateBucketIfNotExists([]byte("ips"))
			if err != nil {
				return fmt.Errorf("create bucket: %s", err)
			}

			for _, v := range ips {
				now := time.Now().Unix()
				ti := strconv.FormatInt(now, 10)
				err := b.Put(v, []byte(ti))
				if err != nil {
					return err
				}
			}

			return nil
		})

		if err != nil {
			return err
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil

}

func GetIpsByTime(minutes string) (sortByteArrays, error) {
	var sba sortByteArrays
	var err error
	d := minutes + "m"
	min, err := time.ParseDuration(d)
	if err != nil {
		return nil, err
	}

	err = db.View(func(tx *bolt.Tx) error {
		var sbaTmp sortByteArrays
		// Assume bucket exists and has keys
		b := tx.Bucket([]byte("ips"))

		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			//https://golang.org/pkg/time/#Parse

			i64, err := strconv.ParseInt(string(v), 10, 64)
			if err != nil {
				return err
			}

			tm := time.Unix(i64, 0)
			tn := time.Now().Add(-min)
			// debug
			//fmt.Printf("%v:%v\n", tm, tn)
			if !tm.Before(tn) {
				sbaTmp = append(sbaTmp, k)
			}
		}

		sba = sbaTmp
		SortByteArrays(sba)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return sba, nil
}

func FormatIpRanges(sba sortByteArrays) []*Address {

	var add []*Address
	var first, last, prev, next net.IP
	var isRange, rangeStart bool

	isRange = false
	rangeStart = false

	for _, v := range sba {
		addr := net.IPAddr{}
		addr.IP = net.IPv4(v[0], v[1], v[2], v[3])
		cur := addr.IP.To4()
		tmpLast := make(net.IP, len(prev))
		copy(tmpLast, prev)
		last = tmpLast

		if bytes.Equal(next, cur) {
			if isRange == false {
				isRange = true
				if rangeStart == false {
					rangeStart = true
					tmpCur := make(net.IP, len(cur))
					copy(tmpCur, cur)
					tmpCur[3]--
					first = tmpCur
				}
			}
		} else {
			if isRange && rangeStart {
				rangeStart = false
				isRange = false
				a := &Address{
					IsRange: true,
					Ip:      fmt.Sprintf("%v-%v", first, last),
				}

				add = append(add, a)

				first = nil
			} else {
				if first == nil && prev != nil {
					a := &Address{
						IsRange: false,
						Ip:      fmt.Sprintf("%v", prev),
					}

					add = append(add, a)
				}
			}

		}

		tmpNext := make(net.IP, len(cur))
		copy(tmpNext, cur)
		next = tmpNext

		if len(next) > 0 {
			next[3]++
		}

		// debug
		/*
			if prev != nil && first != nil {
				line += fmt.Sprintf("# first: %v\tlast: %v\tprev: %v\tcur: %v\tnext: %v\trs: %v\tir: %v\n", first, last, prev, cur, next, rangeStart, isRange)
			}
		*/

		tmpPrev := make(net.IP, len(cur))
		copy(tmpPrev, cur)
		prev = tmpPrev

		// debug
		//fmt.Printf("%v\n", addr.String())
	}

	return add

}

func PowershellHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	vars := mux.Vars(r)
	min := vars["minutes"]
	sba, err := GetIpsByTime(min)
	if err != nil {
		fmt.Fprintf(w, "bad day")
	}

	fips := FormatIpRanges(sba)
	i := len(sba)
	fmt.Fprintf(w, fmt.Sprintf("#total:%v time:%v\n", i, time.Now()))
	fmt.Fprintf(w, "Remove-NetFirewallRule -DisplayName tor\n")
	fmt.Fprintf(w, "$ips = New-Object Collections.Generic.List[String]\n")
	for _, v := range fips {
		s := fmt.Sprintf("$ips.Add('%v');\n", v.Ip)
		fmt.Fprintf(w, s)
	}
	fmt.Fprintf(w, "New-NetFirewallRule -DisplayName tor -Direction Inbound -LocalPort Any -Protocol Any -Action Block -RemoteAddress $ips;")

}

func PaloAltoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	vars := mux.Vars(r)
	min := vars["minutes"]
	sba, err := GetIpsByTime(min)
	if err != nil {
		fmt.Fprintf(w, "bad day")
	}

	fips := FormatIpRanges(sba)
	i := len(sba)
	fmt.Fprintf(w, fmt.Sprintf("#total:%v time:%v\n", i, time.Now()))

	for _, v := range fips {
		fmt.Fprintf(w, v.Ip+"\n")
	}

}

func IptablesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	vars := mux.Vars(r)
	min := vars["minutes"]
	sba, err := GetIpsByTime(min)
	if err != nil {
		fmt.Fprintf(w, "bad day")
	}

	fips := FormatIpRanges(sba)
	i := len(sba)
	fmt.Fprintf(w, fmt.Sprintf("#!/bin/bash\n"))
	fmt.Fprintf(w, fmt.Sprintf("#total:%v time:%v\n", i, time.Now()))
	fmt.Fprintf(w, "iptables -F tor\n")
	fmt.Fprintf(w, "iptables -N tor\n")
	fmt.Fprintf(w, "iptables -A INPUT -j tor\n")

	for _, v := range fips {
		if v.IsRange {
			line := fmt.Sprintf("iptables -A tor -m iprange --src-range %v -j DROP\n", v.Ip)
			fmt.Fprintf(w, line)
		} else {
			line := fmt.Sprintf("iptables -A tor -s %v -j DROP\n", v.Ip)
			fmt.Fprintf(w, line)
		}
	}

}

func CompatHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	vars := mux.Vars(r)
	min := vars["minutes"]
	sba, err := GetIpsByTime(min)
	if err != nil {
		fmt.Fprintf(w, "# (no minutes GET variable submitted")
	}
	i := len(sba)
	fmt.Fprintf(w, fmt.Sprintf("#total:%v %v\n", i, time.Now()))
	fmt.Fprintf(w, "<RequireAll>\n")
	fmt.Fprintf(w, "Require all granted\n")

	for _, v := range sba {
		addr := net.IPAddr{}
		addr.IP = net.IPv4(v[0], v[1], v[2], v[3])
		line := fmt.Sprintf("Require not ip %v\n", addr.String())
		fmt.Fprintf(w, line)

		// debug
		//fmt.Printf("%v\n", addr.String())
	}
	fmt.Fprintf(w, "</RequireAll>")
}

func NginxHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	min := vars["minutes"]
	sba, err := GetIpsByTime(min)
	if err != nil {
		fmt.Fprintf(w, "# (no minutes GET variable submitted")
	}
	i := len(sba)
	fmt.Fprintf(w, fmt.Sprintf("#total:%v %v\n", i, time.Now()))

	for _, v := range sba {
		addr := net.IPAddr{}
		addr.IP = net.IPv4(v[0], v[1], v[2], v[3])
		line := fmt.Sprintf("deny from %v\n", addr.String())
		fmt.Fprintf(w, line)

		// debug
		//fmt.Printf("%v\n", addr.String())
	}
}

func IndexHandler(w http.ResponseWriter, r *http.Request) {
	line := `
	<html>
	<head>
	</head>
	<body>
		<h1>TorHound</h1>
		<p>Toro scrapes the exit relay data from tor.org, caches it, and utilizes the data to create configuration files for blacklisting.</p>
		<p>Note, during scraping, Toro validates and normalizes the data to prevent errors, bugs, or exploits from being passed downstream</p>
		<p>An integer is passed to set the date range.</p>
		<p>Example: https://www.torhound.com/compat/minutes/1440</p>
		<p>The above would indicate you would like all ips that were used by tor exit relays in the last day.</p>
		<ul>
			<li><a href="/compat/minutes/1440">Apache Compat</a></li>
			<li><a href="/nginx/minutes/1440">Nginx</a></li>
			<li><a href="/iptables/minutes/1440">Iptables Firewall</a></li>
			<li><a href="/paloalto/minutes/1440">PaloAlto Firewall</a></li>
			<li><a href="/powershell/minutes/1440/firewall.ps1">Windows PowerShell</a></li>
		</ul>
		<h1>Apache/Nginx</h1>
		<ol>
			<li>Create a cronjob that downloads to the configuration file every (n) minutes, name it tor.conf.</li>
			<li>Adjust your Apache or Nginx conf files to include this conf file</li>
			<li>Gracefully reload the service</li>
		</ol>

		<h1>PaloAlto</h1>
		<ol>
			<li>Simply point your firewall to the configuration using their stated <a href="https://live.paloaltonetworks.com/t5/Featured-Articles/How-to-Block-Tor-The-Onion-Router/ta-p/177648">documentation</a>.</li>
		</ol>
		<h1>Iptables</h1>
		<ol>
			<li>Create a cronjob that downloads to the bash script every (n) minutes.</li>
			<li>Run the script</li>
		</ol>
		<h1>Windows PowerShell</h1>
		<ul>
			<li>Use the following one-liner as a task that downloads the script every (n) minutes and runs it<br>
			<pre>[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; . { iwr -useb https://www.torhound.com/powershell/minutes/1440/firewall.ps1 } | iex;</pre></li>
		</ul>

		<p>Setup your own Toro service easily so as to control your inputs.</p>
		<p>Check out the project on <a href="https://github.com/jaredfolkins/torhound">Github</a>.</p>
	</body>
	</html>
	`
	fmt.Fprintf(w, line)
}
