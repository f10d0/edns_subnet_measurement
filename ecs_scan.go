package main

import (
	"encoding/csv"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	// recursive resolver
	// https://www.iana.org/domains/root/servers
	ROOT_SERVER         = "k.root-servers.net" // RIPE NCC 193.0.14.129 as we are in europe
	ENABLE_CACHE_LOOKUP = true
	TOPLIST_FNAME       = "top-1m.csv"
	SUBNETS_FNAME       = "subnets.txt"
	NUMBER_OF_DOMAINS   = 100
)

var write_chan = make(chan []string, 4096)
var domain_chan = make(chan string, 4096)
var wg_scan sync.WaitGroup
var stop_chan = make(chan interface{})

var subnets = make([]*net.IPNet, 0)

// dns_cache needs to be a tree (typical dns tree)
//
//	        .
//	       / \
//	     com  org
//	    /   \
//	google   amazon
type dns_rr struct {
	nss   []string
	ips   []net.IP
	cname string
}
type cache_node struct {
	node_name string
	next      []*cache_node
	rr        *dns_rr
}

var cache_root cache_node = cache_node{
	node_name: ".",
	next:      make([]*cache_node, 0),
	rr: &dns_rr{
		nss: make([]string, 0),
	},
}

func create_node(domain string) *cache_node {
	domain = strings.ToLower(domain)
	domain_split := strings.Split(domain, ".")
	next_node_name := pop(&domain_split)
	cur_node := &cache_root
	for {
		var found_node *cache_node = nil
		for _, node := range cur_node.next {
			if node.node_name == next_node_name {
				found_node = node
				break
			}
		}
		// if we couldnt find the node
		if found_node == nil {
			// we need to create it
			found_node = &cache_node{
				node_name: next_node_name,
				next:      make([]*cache_node, 0),
				rr: &dns_rr{
					ips: make([]net.IP, 0),
				},
			}
			// and add it to the current node's next list
			cur_node.next = append(cur_node.next, found_node)
		}
		// then we need set the found or created node as cur_node for next it
		cur_node = found_node
		// and pop one from the domain split
		if len(domain_split) != 0 {
			next_node_name = pop(&domain_split)
		} else {
			break
		}
	}
	return cur_node
}

// this gets the deepest node for a given domain
// and a boolean to determine if this is the final answer
func get_node(domain string) (node *cache_node, final bool) {
	domain = strings.ToLower(domain)
	// we get the node iteratively
	log.Println("searching for node", domain)
	domain_split := strings.Split(domain, ".")
	next_node_name := pop(&domain_split)
	cur_node := &cache_root
	for {
		var found_node *cache_node = nil
		for _, node := range cur_node.next {
			if node.node_name == next_node_name {
				found_node = node
				break
			}
		}
		// if we couldnt find the node, we go home
		if found_node == nil {
			return cur_node, false
		}
		// otherwise we need set the found or created node as cur_node for next it
		cur_node = found_node
		// and pop one from the domain split
		if len(domain_split) != 0 {
			next_node_name = pop(&domain_split)
		} else {
			break
		}
	}
	return cur_node, true
}

func preorder(parent *cache_node, level int) {
	log.Println("LEVEL:", level, "| name:", parent.node_name, "| nss:", parent.rr.nss, "| ips", parent.rr.ips)
	for _, child := range parent.next {
		preorder(child, level+1)
	}
}

func cache_update_ns(related_domain string, nameserver string) {
	related_domain = strings.ToLower(related_domain)
	nameserver = strings.ToLower(nameserver)
	log.Println("updating cache for domain", related_domain, "on NS to", nameserver)
	to_update_node := create_node(related_domain)
	contains := false
	// TODO emulate set by using smth like this instead: map[int]bool{1: true, 2: true}
	for _, ns := range to_update_node.rr.nss {
		if ns == nameserver {
			contains = true
			break
		}
	}
	if !contains {
		to_update_node.rr.nss = append(to_update_node.rr.nss, nameserver)
	}
}

func cache_flush_ns(related_domain string) {
	log.Println("flushing ns for", related_domain)
	related_domain = strings.ToLower(related_domain)
	to_update_node := create_node(related_domain)
	to_update_node.rr.nss = make([]string, 0)
}

func cache_update_a(domain string, ip net.IP) {
	domain = strings.ToLower(domain)
	log.Println("updating cache for domain", domain, "on A to", ip)
	to_update_node := create_node(domain)
	contains := false
	for _, it_ip := range to_update_node.rr.ips {
		if it_ip.String() == ip.String() {
			contains = true
			break
		}
	}
	if !contains {
		to_update_node.rr.ips = append(to_update_node.rr.ips, ip)
	}
}

func cache_update_cname(domain string, cname string) {
	domain = strings.ToLower(domain)
	cname = strings.ToLower(cname)
	to_update_node := create_node(domain)
	to_update_node.rr.cname = cname
}

func cache_lookup(domain string) (ips []net.IP, nss []string, cname string) {
	t_start := time.Now()
	domain = strings.ToLower(domain)
	last_node, final := get_node(domain)
	if final {
		log.Println("full cache hit for", domain)
		if last_node.rr.cname != "" {
			return nil, nil, last_node.rr.cname
		}
		ips = last_node.rr.ips
	}
	t_end := time.Now()
	log.Println("cache lookup took", t_end.UnixMicro()-t_start.UnixMicro(), "us")
	return ips, last_node.rr.nss, ""
}

func shuffle[T ~string | interface{}](a []T) {
	rand.Shuffle(len(a), func(i, j int) { (a)[i], (a)[j] = (a)[j], (a)[i] })
}

func pop[T ~string | interface{}](a *[]T) T {
	b := (*a)[len(*a)-1]
	*a = (*a)[:len(*a)-1]
	return b
}

func resolve(domain string, server string) (answers []net.IP, nameserver string) {
	if ENABLE_CACHE_LOOKUP {
		// before we do anything we check the cache
		cache_ips, cache_nss, cache_cname := cache_lookup(domain)
		// should the domain be cnamed we just go from there
		if cache_cname != "" {
			log.Println("cached cname found", domain, "points to", cache_cname)
			return resolve(cache_cname, ROOT_SERVER)
		}
		// otherwise we question the cache if we know one of the ips of the provided nameservers
		// theoretically we could call resolve again here with one randomly chosen nameserver,
		// but then we wouldnt know for which one we would hold the information in cache and just take a random
		// guess at it; i thought it to be best to use the one we have instead of potentially querying for one we dont
		var cache_ns_ips []net.IP
		for _, cache_ns := range cache_nss {
			tmp_cache_ns_ips, _, _ := cache_lookup(cache_ns)
			if len(tmp_cache_ns_ips) != 0 {
				// as soon as we hit, we break and use that one for any further requests (or returns)
				cache_ns_ips = tmp_cache_ns_ips
				break
			}
		}
		// if we have answer ips we return those, and potentially the ns ip
		if len(cache_ips) != 0 {
			if len(cache_ns_ips) != 0 {
				return cache_ips, cache_ns_ips[rand.Intn(len(cache_ns_ips))].String()
			} else {
				return cache_ips, ""
			}
		} else if len(cache_nss) != 0 {
			// in case we dont, we need to query the domain and therefore we need the resolved ns
			ns := cache_nss[rand.Intn(len(cache_nss))]
			ns_ips, _ := resolve(ns, ROOT_SERVER)
			if len(ns_ips) != 0 {
				// we now know the ns ip but not the domain ip
				server = ns_ips[rand.Intn(len(ns_ips))].String()
			} else {
				// at this point for whatever reason the cached nameserver is no longer existent
				// we can continue to query normally without caching
				// but technically we would have to remove the failing cache entry as well TODO
				// and we could also try the others we might have cached but well ...
				log.Println("no ip for cached ns found", ns)
			}
		}
	}

	client := dns.Client{}
	msg := dns.Msg{}
	msg.SetQuestion(domain+".", dns.TypeA)
	log.Println("questioning", server, "for", msg.Question[0].Name)
	rec, _, err := client.Exchange(&msg, server+":53")
	if err != nil {
		log.Println(err)
	}
	if rec == nil {
		log.Println("answer is nil")
		return nil, ""
	}
	if len(rec.Answer) != 0 {
		var answers []net.IP
		var cname string
		for _, ans := range rec.Answer {
			switch ans := ans.(type) {
			case *dns.A:
				answers = append(answers, ans.A)
				cache_update_a(domain, ans.A)
			case *dns.CNAME:
				log.Println("found CNAME", ans.Target, "for", domain)
				cname = ans.Target[:len(ans.Target)-1]
				cache_update_cname(domain, cname)
			}
		}
		// no ip answers -> check the cname
		if len(answers) == 0 {
			return resolve(cname, ROOT_SERVER)
		}
		log.Println("found answers", answers)
		return answers, server
	}
	log.Println("no direct answers found")

	if len(rec.Ns) == 0 {
		log.Println("No Nameservers found")
		return nil, ""
	}

	var related_domain string // assuming all the responses are for the same domain, we assume this anyways with the next new_ns_names
	var new_ns_names []string
	for _, ans := range rec.Ns {
		switch ans := ans.(type) {
		case *dns.NS:
			// update cache tree
			related_domain = ans.Hdr.Name[:len(ans.Hdr.Name)-1]
			new_ns_names = append(new_ns_names, ans.Ns[:len(ans.Ns)-1]) //remove trailing dot, because its appended again by miekg/dns
		}
	}
	//TODO/FIXME?? is this flush even needed?
	cache_flush_ns(related_domain)
	for _, ns_name := range new_ns_names {
		cache_update_ns(related_domain, ns_name)
	}
	log.Println("found next pos nameserver", new_ns_names)

	// if there is data in the additional section we take those
	// (as the nameservers are already resolved)
	if len(rec.Extra) != 0 {
		// list for all the possibly new nameservers
		// so that we can choose one randomly later on
		var new_ns_ips []string
		for _, ans := range rec.Extra {
			switch ans := ans.(type) {
			case *dns.A:
				cache_update_a(ans.Hdr.Name[:len(ans.Hdr.Name)-1], ans.A)
				new_ns_ips = append(new_ns_ips, ans.A.String())
			}
		}
		log.Println("found next Nameservers", new_ns_ips)
		if len(new_ns_ips) > 0 {
			shuffle(new_ns_ips)
			// TODO check: is this rly rng?
			var answers []net.IP
			var used_server string
			for len(answers) == 0 && len(new_ns_ips) != 0 {
				// now we make it recursive
				answers, used_server = resolve(domain, pop(&new_ns_ips)) // FIXME i think this is redundant due to the caching kinda
			}
			return answers, used_server
		}
		//if there are no ips already in the additional section continue with the NS records below
	}

	shuffle(new_ns_names)
	answers = make([]net.IP, 0)
	var used_server string
	for len(answers) == 0 && len(new_ns_names) != 0 {
		// now we need to resolve the nameserver first
		needs_resolving := pop(&new_ns_names)
		ns_answers, _ := resolve(needs_resolving, ROOT_SERVER)
		log.Println("NS ANSWERS:", ns_answers)
		shuffle(ns_answers) // choose nameserver randomly
		//FIXME shuffle
		if len(ns_answers) != 0 {
			// now we make it recursive
			answers, used_server = resolve(domain, ns_answers[0].String())
		}
	}
	if len(answers) == 0 {
		return nil, ""
	}
	return answers, used_server
}

func ecs_query(domain string, ip net.IP, subnet net.IPNet) (answers []net.IP, ecs_subnet *net.IPNet, esc_scope net.IPMask) {

	log.Println("questioning:", ip, "for:", domain, "with subnet:", subnet)

	// Build the message sent to the Auth Server
	msg := dns.Msg{}
	msg.Id = dns.Id()
	msg.RecursionDesired = true
	msg.Question = make([]dns.Question, 1)
	msg.Question[0] = dns.Question{Name: domain + ".", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	msg.Extra = make([]dns.RR, 1)

	// Creating OPT Record
	opt := dns.OPT{}
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT

	// Adding the EDNS0 Subnet Functionality
	e := dns.EDNS0_SUBNET{}
	e.Code = dns.EDNS0SUBNET
	e.Family = 1 // 1 for IPv4 source address, 2 for IPv6
	maskSize, _ := subnet.Mask.Size()
	e.SourceNetmask = uint8(maskSize)
	e.SourceScope = 0
	e.Address = subnet.IP

	opt.Option = append(opt.Option, &e)
	msg.Extra[0] = &opt

	// Making the Query
	rec, err := dns.Exchange(&msg, ip.String()+":53")
	if err != nil {
		log.Println(err)
		return nil, nil, nil
	}
	// Get the returned IP Addresses from the Query
	if len(rec.Answer) != 0 {
		var answers []net.IP
		for _, ans := range rec.Answer {
			switch ans := ans.(type) {
			case *dns.A:
				answers = append(answers, net.IP(ans.A))
			}
		}
		log.Println("found answers", answers)
		// TODO check for ECS field
		return answers, nil, nil
	}

	return nil, nil, nil

}

func request_ns() {
	total_start_t := time.Now()
	exec_sum := 0
	exec_count := 0
	exec_count_avg := 0
	topfile, err := os.Open(TOPLIST_FNAME)
	if err != nil {
		log.Fatal("Unable to read input file " + TOPLIST_FNAME)
	}
	defer topfile.Close()

	csv_reader := csv.NewReader(topfile)
	for {
		records, err := csv_reader.Read()

		if records == nil || exec_count > NUMBER_OF_DOMAINS {
			break
		}

		if err != nil {
			log.Fatal("Unable to parse file as CSV for "+TOPLIST_FNAME, err)
		}

		domain := records[1]
		t_start := time.Now()
		answers, used_server := resolve(domain, ROOT_SERVER)
		t_end := time.Now()

		log.Println("domain:", domain, "answers:", answers, "auth nameserver:", used_server)
		diff_t := t_end.UnixMilli() - t_start.UnixMilli()
		log.Println("request took:", diff_t, "ms")
		exec_count += 1
		if len(answers) != 0 {
			exec_sum += int(diff_t)
			exec_count_avg += 1
		}
		time.Sleep(50 * time.Millisecond)
	}
	log.Println("avg took:", exec_sum/exec_count_avg, "ms, answer ratio:", float64(exec_count_avg)/float64(exec_count))
	total_end_t := time.Now()
	log.Println("total took:", total_end_t.Unix()-total_start_t.Unix(), "s")
}

func writeout() {
	csvfile, err := os.Create("out.csv")
	if err != nil {
		panic(err)
	}
	defer csvfile.Close()

	/*zip_writer := gzip.NewWriter(csvfile)
	defer zip_writer.Flush()*/

	writer := csv.NewWriter(csvfile)
	writer.Comma = ';'
	defer writer.Flush()

	for {
		select {
		case record := <-write_chan:
			writer.Write(record)
			writer.Flush()
		case <-stop_chan:
			return
		}
	}
}

func read_subnets() {
	subnetfile, err := os.Open(SUBNETS_FNAME)
	if err != nil {
		log.Fatal("Unable to read input file " + SUBNETS_FNAME)
	}
	defer subnetfile.Close()

	csv_reader := csv.NewReader(subnetfile)
	for {
		subnet_csv, err := csv_reader.Read()

		if subnet_csv == nil {
			break
		}

		if err != nil {
			log.Fatal("Unable to parse file as CSV for "+SUBNETS_FNAME, err)
		}

		if subnet_csv[0] == "" { // empty line
			continue
		}

		subnet_str := subnet_csv[0]
		_, subnet, err := net.ParseCIDR(subnet_str)
		if err != nil {
			log.Fatal("subnet not in CIDR notation")
		}
		subnets = append(subnets, subnet)
	}
}

func read_toplist() {
	defer wg_scan.Done()
	topfile, err := os.Open(TOPLIST_FNAME)
	if err != nil {
		log.Fatal("Unable to read input file " + TOPLIST_FNAME)
	}
	defer topfile.Close()

	csv_reader := csv.NewReader(topfile)
	var loop_count int = 0
	var domains []string
	for {
		records, err := csv_reader.Read()

		if records == nil || loop_count > NUMBER_OF_DOMAINS {
			break
		}

		if err != nil {
			log.Fatal("Unable to parse file as CSV for "+TOPLIST_FNAME, err)
		}

		domains = append(domains, records[1])
		loop_count += 1
	}
	shuffle(domains)
	//TODO
}

func main_scan() {
	// read list of subnets
	read_subnets()
	// for all subnets
	for subnet := range subnets {
		// read list of topdomains
		go read_toplist()
		// shuffle list
		// scan(list.pop())
		// writeout
	}
}

func main() {
	go writeout()
	//request_ns()
	main_scan()
	log.Println(subnets)

	/*_, subnet, _ := net.ParseCIDR("1.10.10.0/24")*/

	/*t_start = time.Now()
	ecsAnswers := ecs_query(domain, net.ParseIP(used_server), *subnet)
	t_end = time.Now()

	log.Println("ecs answers:", ecsAnswers, "for:", domain, "with:", subnet)
	log.Println("request took:", t_end.UnixMilli()-t_start.UnixMilli(), "ms")*/

	//debug
	log.Println("<=====PREORDER CACHE TREE=====")
	preorder(&cache_root, 0)
	log.Println("========>")
}
