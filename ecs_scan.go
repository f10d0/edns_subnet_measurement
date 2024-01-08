package main

import (
	"log"
	"math/rand"
	"net"
	"time"

	"github.com/miekg/dns"
)

const (
	// recursive resolver
	// https://www.iana.org/domains/root/servers
	root_server = "k.root-servers.net" //RIPE NCC 193.0.14.129
)

func shuffle(a *[]string) {
	rand.Shuffle(len(*a), func(i, j int) { (*a)[i], (*a)[j] = (*a)[j], (*a)[i] })
}

func pop(a *[]string) string {
	b := (*a)[len(*a)-1]
	*a = (*a)[:len(*a)-1]
	return b
}

func resolve(domain string, server string) (answers []net.IP, nameserver string) {
	client := dns.Client{}
	msg := dns.Msg{}
	msg.SetQuestion(domain+".", dns.TypeA)
	log.Println("questioning", server, "for", msg.Question[0].Name)
	rec, _, err := client.Exchange(&msg, server+":53")
	if err != nil {
		log.Println(err)
	}
	if len(rec.Answer) != 0 {
		var answers []net.IP
		var cname string
		for _, ans := range rec.Answer {
			switch ans := ans.(type) {
			case *dns.A:
				answers = append(answers, net.IP(ans.A))
			case *dns.CNAME:
				log.Println("found CNAME", ans.Target, "for", domain)
				cname = ans.Target[:len(ans.Target)-1]
			}
		}
		// no ip answeres -> check the cname
		if len(answers) == 0 {
			return resolve(cname, root_server)
		}
		log.Println("found answers", answers)
		return answers, server
	}
	log.Println("no answers found")

	// if there is data in the additional section we take those
	// as nameservers are already resolved
	if len(rec.Extra) != 0 {
		// list for all the possibly new nameservers
		// so that we can choose one randomly later on
		var new_ns_ips []string
		for _, ans := range rec.Extra {
			switch ans := ans.(type) {
			case *dns.A:
				new_ns_ips = append(new_ns_ips, ans.A.String())
			}
		}
		log.Println("found next Nameservers", new_ns_ips)
		if len(new_ns_ips) > 0 {
			shuffle(&new_ns_ips)
			var answers []net.IP
			var used_server string
			for len(answers) == 0 && len(new_ns_ips) != 0 {
				// now we make it recursive
				answers, used_server = resolve(domain, pop(&new_ns_ips))
			}
			return answers, used_server
		}
		//if there are no ips already in the additional section continue with the NS records below
	}

	if len(rec.Ns) != 0 {
		var new_ns_names []string
		for _, ans := range rec.Ns {
			switch ans := ans.(type) {
			case *dns.NS:
				log.Println("found next pos nameserver", ans.Ns)
				new_ns_names = append(new_ns_names, ans.Ns[:len(ans.Ns)-1]) //remove trailing dot, because its appended again by miekg/dns
			}
		}
		if len(new_ns_names) <= 0 {
			log.Println("No Nameserver found")
			return nil, ""
		}
		shuffle(&new_ns_names)
		var answers []net.IP
		var used_server string
		for len(answers) == 0 && len(new_ns_names) != 0 {
			// now we need to resolve the name of the nameserver first
			ns_answers, _ := resolve(pop(&new_ns_names), root_server)
			log.Println("NS ANWSERS:", ns_answers[0])
			if len(ns_answers) != 0 {
				// now we make it recursive
				answers, used_server = resolve(domain, ns_answers[0].String())
			}
		}
		return answers, used_server
	}
	return nil, ""
}

func ecs_query(domain string, ip net.IP, subnet net.IPNet) (answers []net.IP) {

	log.Println("questioning:", ip, "for:", domain, "with subnet:", subnet)

	// Build the message sent to the Auth Server
	msg := dns.Msg{}
	msg.Id = dns.Id()
	msg.RecursionDesired = true
	msg.Question = make([]dns.Question, 1)
	msg.Question[0] = dns.Question{domain + ".", dns.TypeA, dns.ClassINET}
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
		return nil
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
		return answers
	}

	return nil

}

func main() {

	domain := "chat.openai.com"
	_, subnet, _ := net.ParseCIDR("1.10.10.0/24")

	t_start := time.Now()
	answers, used_server := resolve(domain, root_server)
	t_end := time.Now()

	log.Println("answers:", answers, "auth nameserver:", used_server)
	log.Println("request took:", t_end.UnixMilli()-t_start.UnixMilli(), "ms")

	t_start = time.Now()
	ecsAnswers := ecs_query(domain, net.ParseIP(used_server), *subnet)
	t_end = time.Now()

	log.Println("ecs answers:", ecsAnswers, "for:", domain, "with:", subnet)
	log.Println("request took:", t_end.UnixMilli()-t_start.UnixMilli(), "ms")

}
