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

package cloudflare_ech

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
	records map[uint16][]dns.RR
}

func (n *fakeNext) Exec(_ context.Context, qCtx *query_context.Context) error {
	q := qCtx.Q()
	r := new(dns.Msg)
	r.SetReply(q)
	for _, rr := range n.records[q.Question[0].Qtype] {
		r.Answer = append(r.Answer, dns.Copy(rr))
	}
	qCtx.SetResponse(r)
	return nil
}

func TestRewriteA(t *testing.T) {
	p := mustNewTestPlugin(t, &Args{
		IPv4: []string{"203.0.113.10"},
	})
	qCtx := newTestContext("example.", dns.TypeA)
	cw := sequence.NewChainWalker([]*sequence.ChainNode{{E: &fakeNext{records: map[uint16][]dns.RR{
		dns.TypeA: {
			&dns.A{Hdr: rrh("example.", dns.TypeA), A: net.IPv4(104, 16, 1, 1)},
		},
	}}}}, nil)

	if err := p.Exec(context.Background(), qCtx, cw); err != nil {
		t.Fatal(err)
	}
	got := qCtx.R().Answer[0].(*dns.A).A
	assertIP(t, got, "203.0.113.10")
}

func TestRewriteHTTPSECHForCloudflare(t *testing.T) {
	cfECH := []byte{1, 2, 3}
	p := mustNewTestPlugin(t, &Args{
		IPv4:           []string{"203.0.113.10"},
		CloudflareECH:  "AQID",
		CloudflareALPN: []string{"h2"},
	})
	qCtx := newTestContext("example.", dns.TypeHTTPS)
	cw := sequence.NewChainWalker([]*sequence.ChainNode{{E: &fakeNext{records: map[uint16][]dns.RR{
		dns.TypeHTTPS: {
			&dns.HTTPS{SVCB: dns.SVCB{
				Hdr:      rrh("example.", dns.TypeHTTPS),
				Priority: 1,
				Target:   ".",
				Value: []dns.SVCBKeyValue{
					&dns.SVCBAlpn{Alpn: []string{"http/1.1"}},
				},
			}},
		},
		dns.TypeA: {
			&dns.A{Hdr: rrh("example.", dns.TypeA), A: net.IPv4(104, 16, 1, 1)},
		},
	}}}}, nil)

	if err := p.Exec(context.Background(), qCtx, cw); err != nil {
		t.Fatal(err)
	}
	httpsRR := qCtx.R().Answer[0].(*dns.HTTPS)
	assertALPN(t, httpsRR, []string{"h2"})
	assertECH(t, httpsRR, cfECH)
}

func TestRewriteHTTPSECHForMeta(t *testing.T) {
	metaECH := []byte{4, 5, 6}
	p := mustNewTestPlugin(t, &Args{
		IPv4:             []string{"203.0.113.10"},
		MetaIPv4Prefixes: []string{"157.240.0.0/16"},
		MetaECH:          "BAUG",
		MetaALPN:         []string{"h2"},
	})
	qCtx := newTestContext("example.", dns.TypeHTTPS)
	cw := sequence.NewChainWalker([]*sequence.ChainNode{{E: &fakeNext{records: map[uint16][]dns.RR{
		dns.TypeHTTPS: {
			&dns.HTTPS{SVCB: dns.SVCB{
				Hdr:      rrh("example.", dns.TypeHTTPS),
				Priority: 1,
				Target:   ".",
			}},
		},
		dns.TypeA: {
			&dns.A{Hdr: rrh("example.", dns.TypeA), A: net.IPv4(157, 240, 1, 1)},
		},
	}}}}, nil)

	if err := p.Exec(context.Background(), qCtx, cw); err != nil {
		t.Fatal(err)
	}
	httpsRR := qCtx.R().Answer[0].(*dns.HTTPS)
	assertALPN(t, httpsRR, []string{"h2"})
	assertECH(t, httpsRR, metaECH)
}

func TestParseAddrsFromText(t *testing.T) {
	got := parseAddrsFromText(`{"ips":["104.18.10.118","2606:4700::6812:a76"]}`)
	if len(got) != 2 {
		t.Fatalf("got %d addrs, want 2", len(got))
	}
	if got[0] != netip.MustParseAddr("104.18.10.118") {
		t.Fatalf("unexpected first addr %s", got[0])
	}
	if got[1] != netip.MustParseAddr("2606:4700::6812:a76") {
		t.Fatalf("unexpected second addr %s", got[1])
	}
}

func mustNewTestPlugin(t *testing.T, args *Args) *CloudflareECH {
	t.Helper()
	p, err := NewCloudflareECH(args, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func newTestContext(qname string, qtype uint16) *query_context.Context {
	q := new(dns.Msg)
	q.SetQuestion(qname, qtype)
	return query_context.NewContext(q)
}

func rrh(name string, qtype uint16) dns.RR_Header {
	return dns.RR_Header{Name: name, Rrtype: qtype, Class: dns.ClassINET, Ttl: 60}
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

func assertALPN(t *testing.T, rr *dns.HTTPS, want []string) {
	t.Helper()
	for _, kv := range rr.Value {
		if alpn, ok := kv.(*dns.SVCBAlpn); ok {
			if len(alpn.Alpn) != len(want) {
				t.Fatalf("got alpn %v, want %v", alpn.Alpn, want)
			}
			for i := range want {
				if alpn.Alpn[i] != want[i] {
					t.Fatalf("got alpn %v, want %v", alpn.Alpn, want)
				}
			}
			return
		}
	}
	t.Fatalf("missing alpn")
}

func assertECH(t *testing.T, rr *dns.HTTPS, want []byte) {
	t.Helper()
	for _, kv := range rr.Value {
		if ech, ok := kv.(*dns.SVCBECHConfig); ok {
			if string(ech.ECH) != string(want) {
				t.Fatalf("got ech %v, want %v", ech.ECH, want)
			}
			return
		}
	}
	t.Fatalf("missing ech")
}
