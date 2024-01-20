package main

import (
	"compress/gzip"
	"encoding/csv"
	"log"
	"math/rand"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
	"github.com/miekg/dns"
)

// config
type cfg_db struct {
	Debug                bool   `yaml:"debug"`
	Toplist_fname        string `yaml:"toplist_fname"`
	Subnets_fname        string `yaml:"subnets_fname"`
	Number_of_domains    int    `yaml:"no_of_domains"`
	Simul_ecs_reqs       int    `yaml:"simul_ecs_reqs"`
	Simul_ns_reqs        int    `yaml:"simul_ns_reqs"`
	Routine_stop_timeout int    `yaml:"routine_stop_timeout"`
}

var cfg cfg_db

// effectively constant
// https://www.iana.org/domains/root/servers
var ROOT_SERVER net.IP = net.ParseIP("193.0.14.129") // RIPE NCC "k.root-servers.net" 193.0.14.129 as we are in europe

var write_chan = make(chan *scan_item, 4096)
var write_ns_chan = make(chan *domain_ns_pair, 4096)
var domain_chan = make(chan *domain_ns_pair, 256)
var wg_scan sync.WaitGroup
var stop_write_chan = make(chan interface{})
var domains []*domain_ns_pair = []*domain_ns_pair{}
var domains_mu sync.Mutex
var subnets = make([]*net.IPNet, 0)

func load_config() {
	log.Println("loading config")
	err := cleanenv.ReadConfig("config.yml", &cfg)
	if err != nil {
		panic(err)
	}
}

type domain_ns_pair struct {
	domain string
	nsip   net.IP
}

type scan_item struct {
	domain_ns  *domain_ns_pair
	req_subnet *net.IPNet
	ans_subnet *net.IPNet
	ans_scope  net.IPMask
	ans_ips    []net.IP
}

// the csv format will be as follows:
// timestamp;domain;nameserver-ip;req-subnet-cidr;[ans-subnet-cidr];[ans-scope];[ip1,ip2,...]
func (item *scan_item) to_csv_strarr() []string {
	ret_str := make([]string, 7)
	ret_str[0] = time.Now().Format("2006-01-02 15:04:05.000000")
	ret_str[1] = item.domain_ns.domain
	ret_str[2] = item.domain_ns.nsip.String()
	ret_str[3] = item.req_subnet.String()
	if item.ans_subnet == nil {
		ret_str[4] = ""
	} else {
		ret_str[4] = item.ans_subnet.String()
	}
	if item.ans_scope == nil {
		ret_str[5] = ""
	} else {
		ones, _ := item.ans_scope.Size()
		ret_str[5] = strconv.Itoa(ones)
	}
	ips := ""
	for i, ip := range item.ans_ips {
		ips += ip.String()
		if i < len(item.ans_ips)-1 {
			ips += ","
		}
	}
	ret_str[6] = ips
	return ret_str
}

func writeout() {
	csvfile, err := os.Create("scan.csv.gz")
	if err != nil {
		panic(err)
	}
	defer csvfile.Close()

	zip_writer := gzip.NewWriter(csvfile)
	defer zip_writer.Flush()

	writer := csv.NewWriter(zip_writer)
	writer.Comma = ';'
	defer writer.Flush()

	for {
		select {
		case item := <-write_chan:
			out_str := item.to_csv_strarr()
			//log.Println("writing to file:", out_str)
			writer.Write(out_str)
			//writer.Flush()
		case <-stop_write_chan:
			return
		}
	}
}

func writeout_ns() {
	csvfile, err := os.Create("nameserver.csv.gz")
	if err != nil {
		panic(err)
	}
	defer csvfile.Close()

	zip_writer := gzip.NewWriter(csvfile)
	defer zip_writer.Flush()

	writer := csv.NewWriter(zip_writer)
	writer.Comma = ';'
	defer writer.Flush()
	log.Println("writer for ns entries started")
	for {
		select {
		case pair := <-write_ns_chan:
			log.Println("write_ns_chan", pair)
			var outarr []string = make([]string, 2)
			outarr[0] = pair.domain
			outarr[1] = pair.nsip.String()
			writer.Write(outarr)
			writer.Flush()
		case <-stop_write_chan:
			return
		}
	}
}

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

var tree_mu sync.Mutex

func (parent *cache_node) preorder(level int) {
	log.Println("LEVEL:", level, "| name:", parent.node_name, "| nss:", parent.rr.nss, "| ips", parent.rr.ips)
	for _, child := range parent.next {
		child.preorder(level + 1)
	}
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
	domain_split := strings.Split(domain, ".")
	next_node_name := pop(&domain_split)
	cur_node := &cache_root
	last_ns_node := &cache_root
	// okay hear me out: there is the possibility that a node that is deeper in the
	// tree doesnt provide us with any useful information at all
	// e.g. the following case
	//                    .
	//                  /   \
	//                uy    org
	//              /    \
	//            com
	//           /
	//      random
	// imagine we have received nameserver information for uy. but the domain we want to
	// resolve is google.com.uy. -> without any further checking we would end up at
	// com.uy. which doesnt help us, so we need to check each node for ns entries as well
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
			if len(cur_node.rr.nss) == 0 {
				return last_ns_node, false
			}
			return cur_node, false
		}
		// otherwise we need set the found or created node as cur_node for next it
		cur_node = found_node
		if len(found_node.rr.nss) != 0 {
			last_ns_node = found_node
		}
		// and pop one from the domain split
		if len(domain_split) != 0 {
			next_node_name = pop(&domain_split)
		} else {
			break
		}
	}
	return cur_node, true
}

func cache_update_ns(related_domain string, nameserver string) {
	related_domain = strings.ToLower(related_domain)
	nameserver = strings.ToLower(nameserver)
	tree_mu.Lock()
	//log.Println("updating cache for domain", related_domain, "on NS to", nameserver)
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
	tree_mu.Unlock()
}

func cache_update_a(domain string, ip net.IP) {
	domain = strings.ToLower(domain)
	//log.Println("updating cache for domain", domain, "on A to", ip)
	tree_mu.Lock()
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
	tree_mu.Unlock()
}

func cache_update_cname(domain string, cname string) {
	domain = strings.ToLower(domain)
	cname = strings.ToLower(cname)
	tree_mu.Lock()
	to_update_node := create_node(domain)
	to_update_node.rr.cname = cname
	tree_mu.Unlock()
}

func cache_lookup(domain string) (ips []net.IP, nss []string, cname string, full_hit bool) {
	domain = strings.ToLower(domain)
	last_node, final := get_node(domain)
	if final {
		if last_node.rr.cname != "" {
			return nil, nil, last_node.rr.cname, true
		}
		ips = last_node.rr.ips
	}
	return ips, last_node.rr.nss, "", final
}

func shuffle[T ~string | interface{}](a []T) {
	rand.Shuffle(len(a), func(i, j int) { (a)[i], (a)[j] = (a)[j], (a)[i] })
}

func pop[T ~string | interface{}](a *[]T) T {
	b := (*a)[len(*a)-1]
	*a = (*a)[:len(*a)-1]
	return b
}

func on_blocklist(server net.IP) bool {
	// TODO blocklist ip server ip on blocklist
	return false
}

func resolve(domain string, 道 []string) (answers []net.IP, nameserver net.IP) {
	domain = strings.ToLower(domain)
	道 = append(道, domain)
	if len(道) > 50 {
		log.Println("maximum depth exceeded for", domain)
		return nil, nil
	}

	server := ROOT_SERVER

	// === cache lookup ===
	// before we do anything we check the cache
	cache_ips, cache_nss, cache_cname, definitive := cache_lookup(domain)
	// its storytime again; cases like these exist:
	// dig @193.0.9.84 NS1.NULL1.kg A
	// ;; AUTH
	//   NULL1.KG.		86400	IN	NS	NS2.NULL1.KG.
	//   NULL1.KG.		86400	IN	NS	NS1.NULL1.KG.
	// ;; ADDITIONAL
	//   n/a
	// 193.0.9.84 (kg.cctld.authdns.ripe.net.) is the toplvl ns responsible for kg.
	// what does this tell us? ダメだーー！
	if slices.Contains(cache_nss, domain) {
		return nil, nil
	}
	// should the domain be cnamed we just go from there
	if cache_cname != "" {
		log.Println("cached cname found", domain, "points to", cache_cname)
		return resolve(cache_cname, 道)
	}
	// otherwise we question the cache if we know one of the ips of the provided nameservers
	// theoretically we could call resolve again here with one randomly chosen nameserver,
	// but then we wouldnt know for which one we would hold the information in cache and just take a random
	// guess at it; i thought it to be best to use the one we have instead of potentially querying for one we dont
	var cache_ns_ips []net.IP
	// TODO shuffle cache_nss??
	for _, cache_ns := range cache_nss {
		// TODO i wonder if this should better be a resolve(cache_only=true),
		// because what if the nameserver is cnamed?
		tmp_cache_ns_ips, _, _, _ := cache_lookup(cache_ns)
		if len(tmp_cache_ns_ips) != 0 {
			// as soon as we hit, we break and use that one for any further requests (or returns)
			cache_ns_ips = tmp_cache_ns_ips
			break
		}
	}
	// if we have answer ips we return those, and potentially the ns ip
	if len(cache_ips) != 0 {
		if len(cache_ns_ips) != 0 {
			return cache_ips, cache_ns_ips[rand.Intn(len(cache_ns_ips))]
		} else {
			return cache_ips, nil
		}
	} else if len(cache_ns_ips) != 0 {
		server = cache_ns_ips[rand.Intn(len(cache_ns_ips))]
	} else if len(cache_nss) != 0 {
		// in case we dont, we need to query the domain and therefore we need the resolved ns
		ns := cache_nss[rand.Intn(len(cache_nss))]
		ns_ips, _ := resolve(ns, 道)
		if len(ns_ips) != 0 {
			// we now know the ns ip but not the domain ip
			server = ns_ips[rand.Intn(len(ns_ips))]
		} else {
			// at this point for whatever reason the cached nameserver is no longer existent
			// we can continue to query normally without caching
			// but technically we would have to remove the failing cache entry as well TODO
			// and we could also try the others we might have cached but well ...
			log.Println("no ip for cached ns found", ns)
		}
	}
	if on_blocklist(server) {
		return nil, nil
	}

	// === make & send the actual dns query ===
	client := dns.Client{}
	client.Timeout = 5 * time.Second
	msg := dns.Msg{}
	msg.SetQuestion(domain+".", dns.TypeA)
	log.Println("questioning", server, "for", msg.Question[0].Name)
	rec, _, err := client.Exchange(&msg, server.String()+":53")
	if err != nil {
		log.Println(err)
	}

	// === handle the response ===
	if rec == nil {
		log.Println("answer is nil")
		return nil, nil
	}
	if len(rec.Answer) != 0 {
		var answers []net.IP
		var cname string = ""
		for _, ans := range rec.Answer {
			switch ans := ans.(type) {
			case *dns.A:
				answers = append(answers, ans.A)
				if 道[0] != domain { // dont need to cache the original domain, as it is only looked up once
					cache_update_a(domain, ans.A)
				}
			case *dns.CNAME:
				log.Println("found CNAME", ans.Target, "for", domain)
				cname = ans.Target[:len(ans.Target)-1]
				if 道[0] != domain {
					cache_update_cname(domain, cname)
				}
			}
		}
		// no ip answers -> check the cname
		if len(answers) == 0 && cname != "" {
			return resolve(cname, 道)
		}
		log.Println("resolve found answers", answers, "for domain", domain)
		return answers, server
	} else if definitive {
		// return empty-handed (◡︵◡)
		return nil, nil
	}
	log.Println("no direct answers found")

	if len(rec.Ns) == 0 {
		log.Println("no nameservers found")
		return nil, nil
	}

	var new_ns_names []string
	var related_domain string // assuming all the responses are for the same domain
	for _, ans := range rec.Ns {
		switch ans := ans.(type) {
		case *dns.NS:
			related_domain = ans.Hdr.Name[:len(ans.Hdr.Name)-1] //remove trailing dot, as it's appended again by miekg/dns
			ns_name := ans.Ns[:len(ans.Ns)-1]
			new_ns_names = append(new_ns_names, ns_name)
			// update cache tree
			cache_update_ns(related_domain, ns_name)
		}
	}
	log.Println("found next pos nameserver", new_ns_names, "related domain", related_domain)

	// if there is data in the additional section we take those
	// (as the nameservers are already resolved)
	if len(rec.Extra) != 0 {
		// list for all the possibly new nameservers
		// so that we can choose one randomly later on
		var new_ns_ips []net.IP
		for _, ans := range rec.Extra {
			switch ans := ans.(type) {
			case *dns.A:
				related_domain := ans.Hdr.Name[:len(ans.Hdr.Name)-1]
				cache_update_a(related_domain, ans.A)
				new_ns_ips = append(new_ns_ips, ans.A)
			}
		}
		log.Println("found next nameserver ips", new_ns_ips)
	}

	if len(new_ns_names) != 0 {
		return resolve(domain, 道)
	}
	return nil, nil
}

func ecs_query(domain string, nsip net.IP, subnet *net.IPNet) (answers []net.IP, ecs_subnet *net.IPNet, ecs_scope net.IPMask) {

	// log.Println("ecs questioning:", nsip, "for:", domain, "with subnet:", subnet)

	client := dns.Client{}
	client.Timeout = 5 * time.Second
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
	rec, _, err := client.Exchange(&msg, nsip.String()+":53")
	if err != nil {
		log.Println(err)
		return nil, nil, nil
	}
	answers = make([]net.IP, 0)
	// Get the returned IP Addresses from the Query
	if len(rec.Answer) != 0 {
		for _, ans := range rec.Answer {
			switch ans := ans.(type) {
			case *dns.A:
				answers = append(answers, net.IP(ans.A))
			}
		}
		//log.Println("ecs found answers", answers)
	}
	for _, rr := range rec.Extra {
		if opt, ok := rr.(*dns.OPT); ok {
			// Iterate over the EDNS0 options
			for _, opt := range opt.Option {
				if ecs, ok := opt.(*dns.EDNS0_SUBNET); ok {
					// ECS information found
					mask := net.CIDRMask(int(ecs.SourceNetmask), 32)
					ecs_subnet = &net.IPNet{IP: ecs.Address, Mask: mask}
					ecs_scope = net.CIDRMask(int(ecs.SourceScope), 32)
					return answers, ecs_subnet, ecs_scope
				}
			}
		}
	}

	return nil, nil, nil
}

func read_subnets() {
	log.Println("reading subnets")
	subnetfile, err := os.Open(cfg.Subnets_fname)
	if err != nil {
		log.Fatal("Unable to read input file " + cfg.Subnets_fname)
	}
	defer subnetfile.Close()

	csv_reader := csv.NewReader(subnetfile)
	for {
		subnet_csv, err := csv_reader.Read()

		if subnet_csv == nil {
			break
		}

		if err != nil {
			log.Fatal("Unable to parse file as CSV for "+cfg.Subnets_fname, err)
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
	log.Println("read subnets:", subnets)
}

func read_toplist() {
	log.Println("reading toplist")
	topfile, err := os.Open(cfg.Toplist_fname)
	if err != nil {
		log.Fatal("Unable to read input file " + cfg.Toplist_fname)
	}
	defer topfile.Close()

	csv_reader := csv.NewReader(topfile)

	loop_count := 0
	for {
		records, err := csv_reader.Read()

		if records == nil || cfg.Number_of_domains != -1 && loop_count > cfg.Number_of_domains {
			break
		}
		if err != nil {
			log.Fatal("Unable to parse file as CSV for "+cfg.Toplist_fname, err)
		}
		loop_count++

		domain := records[1]
		domains_mu.Lock()
		domains = append(domains, &domain_ns_pair{
			domain: domain,
			nsip:   nil, // for now we dont have nothing
		})
		domains_mu.Unlock()
	}
	log.Println("read", len(domains), "toplist entries")
}

type ns_worker struct {
	stop_chan chan interface{}
}

func (worker *ns_worker) request() {
	defer wg_scan.Done()
	worker.stop_chan = make(chan interface{})
	for {
		select {
		case domain_ns := <-domain_chan:
			domain := domain_ns.domain
			t_start := time.Now()
			answers, used_server := resolve(domain, []string{})
			t_end := time.Now()
			diff_t := t_end.UnixMilli() - t_start.UnixMilli()
			log.Println("domain:", domain, "answers:", answers, "auth nameserver:", used_server, "took:", diff_t, "ms")
			if len(answers) == 0 {
				continue
			}
			domain_ns.nsip = used_server
			write_ns_chan <- domain_ns
		case <-worker.stop_chan:
			return
		}
	}
}

func query_ns() {
	log.Println("getting all the nameservers")
	log.Println("starting", cfg.Simul_ns_reqs, "nameserver request routines")
	total_start_t := time.Now()
	var ns_workers []*ns_worker = make([]*ns_worker, 0)
	for i := 0; i < cfg.Simul_ns_reqs; i++ {
		wg_scan.Add(1)
		worker := &ns_worker{}
		ns_workers = append(ns_workers, worker)
		go worker.request()
	}
	go func() {
		shuffle(domains)
		for _, domain_ns := range domains {
			domain_chan <- domain_ns
		}
		log.Println("waiting to end ns request workers")
		time.Sleep(time.Duration(cfg.Routine_stop_timeout) * time.Second)
		log.Println("ending workers")
		for _, worker := range ns_workers {
			close(worker.stop_chan)
		}
	}()
	wg_scan.Wait()
	total_end_t := time.Now()
	log.Println("ns-req, total took:", total_end_t.Unix()-total_start_t.Unix(), "s")
}

type scan_worker struct {
	stop_scan chan interface{}
}

func (scanner *scan_worker) scan(subnet *net.IPNet) {
	scanner.stop_scan = make(chan interface{})
	defer wg_scan.Done()
	for {
		select {
		case domain_ns := <-domain_chan:
			// continue if none
			if domain_ns.nsip == nil {
				continue
			}
			// query the nameserver
			ips, ecs_net, ecs_scope := ecs_query(domain_ns.domain, domain_ns.nsip, subnet)
			// hand to write_chan (づ˶•༝•˶)
			write_chan <- &scan_item{
				domain_ns:  domain_ns,
				req_subnet: subnet,
				ans_subnet: ecs_net,
				ans_scope:  ecs_scope,
				ans_ips:    ips,
			}
		case <-scanner.stop_scan:
			return
		}
	}
}

func query_ecs() {
	log.Println("starting main scan")
	go writeout()
	// read list of subnets
	read_subnets()
	// for all subnets
	for i, subnet := range subnets {
		log.Println("scanning subnet", i, subnet.String())
		// start all the scanners
		var scanners []*scan_worker = make([]*scan_worker, 0)
		for i := 0; i < cfg.Simul_ecs_reqs; i++ {
			scanner := &scan_worker{}
			scanners = append(scanners, scanner)
			wg_scan.Add(1)
			go scanner.scan(subnet)
		}
		// read list of topdomains
		go func() {
			shuffle(domains)
			for _, domain := range domains {
				domain_chan <- domain
			}
			// wait a gracious x seconds until all dns requests are complete
			log.Println("waiting to end this round")
			time.Sleep(time.Duration(cfg.Routine_stop_timeout) * time.Second)
			log.Println("stopping scanner now")
			for _, scanner := range scanners {
				close(scanner.stop_scan)
			}
		}()
		wg_scan.Wait()
	}
}

func main() {
	log.Println(("starting program"))
	go writeout_ns()
	load_config()
	read_toplist()
	query_ns()
	//debug
	log.Println("<=====PREORDER CACHE TREE=====")
	cache_root.preorder(0)
	log.Println("========>")
	// flush the dns cache tree as we dont need it any longer
	// all the relevant nameservers are stored as domain_ns_pair
	cache_root.next = make([]*cache_node, 0)
	query_ecs()
	time.Sleep(5 * time.Second)
	close(stop_write_chan)
	time.Sleep(5 * time.Second) // wait to write all data completely to file
	log.Println("program end")
}
