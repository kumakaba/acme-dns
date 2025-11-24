package nameserver

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func (n *Nameserver) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	m := new(dns.Msg)
	m.SetReply(r)
	// handle edns0
	opt := r.IsEdns0()
	if opt != nil {
		if opt.Version() != 0 {
			// Only EDNS0 is standardized
			m.Rcode = dns.RcodeBadVers
			m.SetEdns0(512, false)
		} else {
			// We can safely do this as we know that we're not setting other OPT RRs within acme-dns.
			m.SetEdns0(512, false)
			if r.Opcode == dns.OpcodeQuery {
				n.readQuery(ctx, m)
			}
		}
	} else {
		if r.Opcode == dns.OpcodeQuery {
			n.readQuery(ctx, m)
		}
	}
	_ = w.WriteMsg(m)
}

func (n *Nameserver) getSOARecord() dns.RR {
	if n.SOA == nil {
		return nil
	}
	originalSOA, ok := n.SOA.(*dns.SOA)
	if !ok {
		return n.SOA
	}
	soaCopy := *originalSOA
	soaCopy.Hdr.Ttl = 1
	soaCopy.Minttl = 1
	return &soaCopy
}

func (n *Nameserver) readQuery(ctx context.Context, m *dns.Msg) {
	var authoritative = false
	for _, que := range m.Question {
		if rr, rc, auth, err := n.answer(ctx, que); err == nil {
			if auth {
				authoritative = auth
			}
			m.Rcode = rc
			m.Answer = append(m.Answer, rr...)
		}
	}
	m.Authoritative = authoritative
	if authoritative {
		if m.Rcode == dns.RcodeNameError {
			m.Ns = append(m.Ns, n.getSOARecord())
		}
		if m.Rcode == dns.RcodeSuccess && len(m.Answer) == 0 {
			m.Ns = append(m.Ns, n.getSOARecord())
		}
	}
}

func (n *Nameserver) answer(ctx context.Context, q dns.Question) ([]dns.RR, int, bool, error) {
	var rcode = dns.RcodeSuccess
	var err error
	var txtRRs []dns.RR
	var authoritative = n.isAuthoritative(q)

	var answers []dns.RR

	if !authoritative {
		n.Logger.Debugw("Refused question for domain",
			"qtype", dns.TypeToString[q.Qtype],
			"domain", q.Name,
			"rcode", dns.RcodeToString[dns.RcodeRefused])
		return nil, dns.RcodeRefused, false, nil // REFUSED
	}
	if !n.isOwnChallenge(q.Name) && !n.answeringForDomain(q.Name) {
		rcode = dns.RcodeNameError // NXDOMAIN
	}

	r, _ := n.getRecord(q)
	answers = append(answers, r...)
	if q.Qtype == dns.TypeTXT {
		if n.isOwnChallenge(q.Name) {
			txtRRs, err = n.answerOwnChallenge(q)
		} else {
			txtRRs, err = n.answerTXT(ctx, q)
		}
		if err == nil {
			answers = append(answers, txtRRs...)
		}
	}
	if len(answers) > 0 {
		rcode = dns.RcodeSuccess
	}

	n.Logger.Debugw("Answering question for domain",
		"qtype", dns.TypeToString[q.Qtype],
		"domain", q.Name,
		"rcode", dns.RcodeToString[rcode],
		"answer_count", len(answers))
	return answers, rcode, authoritative, nil
}

func (n *Nameserver) answerTXT(ctx context.Context, q dns.Question) ([]dns.RR, error) {
	var ra []dns.RR
	subdomain := sanitizeDomainQuestion(q.Name)
	atxt, err := n.DB.GetTXTForDomain(ctx, subdomain)
	if err != nil {
		n.Logger.Errorw("Error while trying to get record",
			"error", err.Error())
		return ra, err
	}
	for _, v := range atxt {
		if len(v) > 0 {
			r := new(dns.TXT)
			r.Hdr = dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1}
			r.Txt = append(r.Txt, v)
			ra = append(ra, r)
		}
	}
	return ra, nil
}

func (n *Nameserver) isAuthoritative(q dns.Question) bool {
	if n.answeringForDomain(q.Name) {
		return true
	}
	domainParts := strings.Split(strings.ToLower(q.Name), ".")
	for i := range domainParts {
		if n.answeringForDomain(strings.Join(domainParts[i:], ".")) {
			return true
		}
	}
	return false
}

// isOwnChallenge checks if the query is for the domain of this acme-dns instance. Used for answering its own ACME challenges
func (n *Nameserver) isOwnChallenge(name string) bool {
	domainParts := strings.SplitN(name, ".", 2)
	if len(domainParts) == 2 {
		if strings.ToLower(domainParts[0]) == "_acme-challenge" {
			domain := strings.ToLower(domainParts[1])
			if !strings.HasSuffix(domain, ".") {
				domain = domain + "."
			}
			if domain == n.OwnDomain {
				return true
			}
		}
	}
	return false
}

// answeringForDomain checks if we have any records for a domain
func (n *Nameserver) answeringForDomain(name string) bool {
	if n.OwnDomain == strings.ToLower(name) {
		return true
	}
	_, ok := n.Domains[strings.ToLower(name)]
	return ok
}

func (n *Nameserver) getRecord(q dns.Question) ([]dns.RR, error) {
	var rr []dns.RR
	var cnames []dns.RR
	domain, ok := n.Domains[strings.ToLower(q.Name)]
	if !ok {
		return rr, fmt.Errorf("no records for domain %s", q.Name)
	}
	for _, ri := range domain.Records {
		if ri.Header().Rrtype == q.Qtype {
			rr = append(rr, ri)
		}
		if ri.Header().Rrtype == dns.TypeCNAME {
			cnames = append(cnames, ri)
		}
	}
	if len(rr) == 0 {
		return cnames, nil
	}
	return rr, nil
}
