package dns

// Tests that solve that an specific issue.

import (
	"strings"
	"testing"
)

func TestTCPRtt(t *testing.T) {
	m := new(Msg)
	m.RecursionDesired = true
	m.SetQuestion("example.org.", TypeA)

	c := &Client{}
	for _, proto := range []string{"udp", "tcp"} {
		c.Net = proto
		_, rtt, err := c.Exchange(m, "8.8.4.4:53")
		if err != nil {
			t.Fatal(err)
		}
		if rtt == 0 {
			t.Fatalf("expecting non zero rtt %s, got zero", c.Net)
		}
	}
}

func TestNSEC3MissingSalt(t *testing.T) {
	rr := testRR("ji6neoaepv8b5o6k4ev33abha8ht9fgc.example. NSEC3 1 1 12 aabbccdd K8UDEMVP1J2F7EG6JEBPS17VP3N8I58H")
	m := new(Msg)
	m.Answer = []RR{rr}
	mb, err := m.Pack()
	if err != nil {
		t.Fatalf("expected to pack message. err: %s", err)
	}
	if err := m.Unpack(mb); err != nil {
		t.Fatalf("expected to unpack message. missing salt? err: %s", err)
	}
	in := rr.(*NSEC3).Salt
	out := m.Answer[0].(*NSEC3).Salt
	if in != out {
		t.Fatalf("expected salts to match. packed: `%s`. returned: `%s`", in, out)
	}
}

func TestNSEC3MixedNextDomain(t *testing.T) {
	rr := testRR("ji6neoaepv8b5o6k4ev33abha8ht9fgc.example. NSEC3 1 1 12 - k8udemvp1j2f7eg6jebps17vp3n8i58h")
	m := new(Msg)
	m.Answer = []RR{rr}
	mb, err := m.Pack()
	if err != nil {
		t.Fatalf("expected to pack message. err: %s", err)
	}
	if err := m.Unpack(mb); err != nil {
		t.Fatalf("expected to unpack message. err: %s", err)
	}
	in := strings.ToUpper(rr.(*NSEC3).NextDomain)
	out := m.Answer[0].(*NSEC3).NextDomain
	if in != out {
		t.Fatalf("expected round trip to produce NextDomain `%s`, instead `%s`", in, out)
	}
}

func TestErrorPackUnpack(t *testing.T) {
	m := new(Msg)
	m.SetQuestion("3.6.9.4.7.1.7.1.5.6.8.9.4.e164.arpa.", TypeNAPTR)
	rply := new(Msg)
	rply.SetReply(m)
	//add answer as NAPTR
	if len(rply.Answer) == 0 {
		rply.Answer = append(rply.Answer,
			&NAPTR{
				Hdr: RR_Header{
					Name:   m.Question[0].Name,
					Rrtype: m.Question[0].Qtype,
					Class:  ClassINET,
					Ttl:    60},
			},
		)
	}
	itm := "/urn:cid:.+@([^\\092.]+\\092.)(.*)$/\\0922/i"
	rply.Answer[len(rply.Answer)-1].(*NAPTR).Regexp = itm
	// Pack msg and then unpack into msg2
	buf, err := rply.Pack()
	if err != nil {
		t.Fatalf("rply.Pack failed: %v", err)
	}
	itm = "/urn:cid:.+@([^\\.]+\\.)(.*)$/\\2/i"
	var msg2 Msg
	if err := msg2.Unpack(buf); err != nil {
		t.Fatalf("msg2.Unpack failed: %v", err)
	}
	if msg2.Answer[0].(*NAPTR).Regexp != itm {
		t.Errorf("\nExpecting : <%+v>, but received <%+v> \n", itm, msg2.Answer[0].(*NAPTR).Regexp)
	}
}

func TestErrorPackUnpack2(t *testing.T) {
	m := new(Msg)
	m.SetQuestion("3.6.9.4.7.1.7.1.5.6.8.9.4.e164.arpa.", TypeNAPTR)
	rply := new(Msg)
	rply.SetReply(m)
	//add answer as NAPTR
	if len(rply.Answer) == 0 {
		rply.Answer = append(rply.Answer,
			&NAPTR{
				Hdr: RR_Header{
					Name:   m.Question[0].Name,
					Rrtype: m.Question[0].Qtype,
					Class:  ClassINET,
					Ttl:    60},
			},
		)
	}
	itm := "/urn:cid:.+@([^\\\\.]+\\\\.)(.*)$/\\\\2/i"
	rply.Answer[len(rply.Answer)-1].(*NAPTR).Regexp = itm
	// Pack msg and then unpack into msg2
	buf, err := rply.Pack()
	if err != nil {
		t.Fatalf("rply.Pack failed: %v", err)
	}
	itm = "/urn:cid:.+@([^\\.]+\\.)(.*)$/\\2/i"
	var msg2 Msg
	if err := msg2.Unpack(buf); err != nil {
		t.Fatalf("msg2.Unpack failed: %v", err)
	}
	if msg2.Answer[0].(*NAPTR).Regexp != itm {
		t.Errorf("\nExpecting : <%+v>, but received <%+v> \n", itm, msg2.Answer[0].(*NAPTR).Regexp)
	}
}

func TestErrorPackUnpack3(t *testing.T) {
	m := new(Msg)
	m.SetQuestion("3.6.9.4.7.1.7.1.5.6.8.9.4.e164.arpa.", TypeNAPTR)
	rply := new(Msg)
	rply.SetReply(m)
	//add answer as NAPTR
	if len(rply.Answer) == 0 {
		rply.Answer = append(rply.Answer,
			&NAPTR{
				Hdr: RR_Header{
					Name:   m.Question[0].Name,
					Rrtype: m.Question[0].Qtype,
					Class:  ClassINET,
					Ttl:    60},
			},
		)
	}
	itm := `/urn:cid:.+@([^\\.]+\\.)(.*)$/\\2/i`
	rply.Answer[len(rply.Answer)-1].(*NAPTR).Regexp = itm
	// Pack msg and then unpack into msg2
	buf, err := rply.Pack()
	if err != nil {
		t.Fatalf("rply.Pack failed: %v", err)
	}
	itm = "/urn:cid:.+@([^\\.]+\\.)(.*)$/\\2/i"
	var msg2 Msg
	if err := msg2.Unpack(buf); err != nil {
		t.Fatalf("msg2.Unpack failed: %v", err)
	}
	if msg2.Answer[0].(*NAPTR).Regexp != itm {
		t.Errorf("\nExpecting : <%+v>, but received <%+v> \n", itm, msg2.Answer[0].(*NAPTR).Regexp)
	}
}
