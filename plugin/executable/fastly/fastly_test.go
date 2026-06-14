/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package fastly

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

type fakeNext struct {
	records map[string]map[uint16][]dns.RR
}

func (n *fakeNext) Exec(_ context.Context, qCtx *query_context.Context) error {
	q := qCtx.Q()
	r := new(dns.Msg)
	r.SetReply(q)
	if byType := n.records[q.Question[0].Name]; byType != nil {
		for _, rr := range byType[q.Question[0].Qtype] {
			r.Answer = append(r.Answer, dns.Copy(rr))
		}
	}
	if len(r.Answer) == 0 {
		r = genEmptyReply(q)
	}
	qCtx.SetResponse(r)
	return nil
}

func TestFastly_RedirectAByCNAME(t *testing.T) {
	p := mustNewFastly(t, nil)
	qCtx := newTestContext("cache.nixos.org.", dns.TypeA)
	cw := sequence.NewChainWalker([]*sequence.ChainNode{{E: &fakeNext{records: map[string]map[uint16][]dns.RR{
		"cache.nixos.org.": {
			dns.TypeA: {
				&dns.CNAME{Hdr: rrh("cache.nixos.org.", dns.TypeCNAME), Target: "dualstack.n.sni.global.fastly.net."},
				&dns.A{Hdr: rrh("dualstack.n.sni.global.fastly.net.", dns.TypeA), A: net.IPv4(151, 101, 1, 91)},
			},
		},
		defaultPreferredDomain: {
			dns.TypeA: {
				&dns.A{Hdr: rrh(defaultPreferredDomain, dns.TypeA), A: net.IPv4(203, 0, 113, 10)},
			},
		},
	}}}}, nil)

	if err := p.Exec(context.Background(), qCtx, cw); err != nil {
		t.Fatal(err)
	}
	assertCNAME(t, qCtx.R().Answer[0], "cache.nixos.org.", defaultPreferredDomain)
	got := qCtx.R().Answer[1].(*dns.A).A
	assertIP(t, got, "203.0.113.10")
}

func TestFastly_RedirectAAAAByFastlyIP(t *testing.T) {
	p := mustNewFastly(t, &Args{PreferredDomain: "fastly.example."})
	qCtx := newTestContext("example.org.", dns.TypeAAAA)
	cw := sequence.NewChainWalker([]*sequence.ChainNode{{E: &fakeNext{records: map[string]map[uint16][]dns.RR{
		"example.org.": {
			dns.TypeAAAA: {
				&dns.AAAA{Hdr: rrh("example.org.", dns.TypeAAAA), AAAA: net.ParseIP("2a04:4e42:400::347")},
			},
		},
		"fastly.example.": {
			dns.TypeAAAA: {
				&dns.AAAA{Hdr: rrh("fastly.example.", dns.TypeAAAA), AAAA: net.ParseIP("2001:db8::1")},
			},
		},
	}}}}, nil)

	if err := p.Exec(context.Background(), qCtx, cw); err != nil {
		t.Fatal(err)
	}
	assertCNAME(t, qCtx.R().Answer[0], "example.org.", "fastly.example.")
	got := qCtx.R().Answer[1].(*dns.AAAA).AAAA
	assertIP(t, got, "2001:db8::1")
}

func TestFastly_SkipNonFastly(t *testing.T) {
	p := mustNewFastly(t, nil)
	qCtx := newTestContext("example.org.", dns.TypeA)
	cw := sequence.NewChainWalker([]*sequence.ChainNode{{E: &fakeNext{records: map[string]map[uint16][]dns.RR{
		"example.org.": {
			dns.TypeA: {
				&dns.A{Hdr: rrh("example.org.", dns.TypeA), A: net.IPv4(203, 0, 113, 20)},
			},
		},
	}}}}, nil)

	if err := p.Exec(context.Background(), qCtx, cw); err != nil {
		t.Fatal(err)
	}
	if got := len(qCtx.R().Answer); got != 1 {
		t.Fatalf("got %d answers, want 1", got)
	}
	got := qCtx.R().Answer[0].(*dns.A).A
	assertIP(t, got, "203.0.113.20")
}

func TestFastly_RedirectEvenWhenPreferredHasNoAddress(t *testing.T) {
	p := mustNewFastly(t, nil)
	qCtx := newTestContext("cache.nixos.org.", dns.TypeA)
	cw := sequence.NewChainWalker([]*sequence.ChainNode{{E: &fakeNext{records: map[string]map[uint16][]dns.RR{
		"cache.nixos.org.": {
			dns.TypeA: {
				&dns.CNAME{Hdr: rrh("cache.nixos.org.", dns.TypeCNAME), Target: "dualstack.n.sni.global.fastly.net."},
				&dns.A{Hdr: rrh("dualstack.n.sni.global.fastly.net.", dns.TypeA), A: net.IPv4(151, 101, 1, 91)},
			},
		},
	}}}}, nil)

	if err := p.Exec(context.Background(), qCtx, cw); err != nil {
		t.Fatal(err)
	}
	assertCNAME(t, qCtx.R().Answer[0], "cache.nixos.org.", defaultPreferredDomain)
	if got := len(qCtx.R().Answer); got != 1 {
		t.Fatalf("got %d answers, want CNAME-only response", got)
	}
}

func TestQuickSetup(t *testing.T) {
	p, err := QuickSetup(nil, "fastly.example.")
	if err != nil {
		t.Fatal(err)
	}
	f, ok := p.(*Fastly)
	if !ok {
		t.Fatalf("QuickSetup returned %T, want *Fastly", p)
	}
	if f.preferredDomain != "fastly.example." {
		t.Fatalf("got preferred domain %s, want fastly.example.", f.preferredDomain)
	}
}

func mustNewFastly(t *testing.T, args *Args) *Fastly {
	t.Helper()
	f, err := NewFastly(args)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func newTestContext(qname string, qtype uint16) *query_context.Context {
	q := new(dns.Msg)
	q.SetQuestion(qname, qtype)
	return query_context.NewContext(q)
}

func rrh(name string, qtype uint16) dns.RR_Header {
	return dns.RR_Header{Name: name, Rrtype: qtype, Class: dns.ClassINET, Ttl: 60}
}

func assertCNAME(t *testing.T, rr dns.RR, name, target string) {
	t.Helper()
	cname, ok := rr.(*dns.CNAME)
	if !ok {
		t.Fatalf("got %T, want *dns.CNAME", rr)
	}
	if cname.Hdr.Name != name {
		t.Fatalf("got CNAME owner %s, want %s", cname.Hdr.Name, name)
	}
	if cname.Target != target {
		t.Fatalf("got CNAME target %s, want %s", cname.Target, target)
	}
}

func assertIP(t *testing.T, got net.IP, want string) {
	t.Helper()
	gotAddr, ok := addrFromIP4(got)
	if !ok {
		gotAddr, ok = addrFromIP6(got)
	}
	if !ok {
		t.Fatalf("invalid IP %v", got)
	}
	wantAddr := netip.MustParseAddr(want)
	if gotAddr != wantAddr {
		t.Fatalf("got %s, want %s", gotAddr, wantAddr)
	}
}
