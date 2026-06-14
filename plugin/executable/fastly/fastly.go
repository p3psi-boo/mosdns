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
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

const PluginType = "fastly"

const (
	defaultPreferredDomain = "fastly.182682.xyz."
	defaultCNAMETTL        = 60
)

var (
	defaultMatchCNAMEs = []string{
		"fastly.net.",
		"fastlylb.net.",
	}
	defaultMatchIPv4Prefixes = []string{
		"151.101.0.0/16",
		"146.75.0.0/16",
		"167.82.0.0/16",
		"199.232.0.0/16",
	}
	defaultMatchIPv6Prefixes = []string{
		"2a04:4e42::/32",
	}
)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
	sequence.MustRegExecQuickSetup(PluginType, QuickSetup)
}

type Args struct {
	PreferredDomain   string   `yaml:"preferred_domain"`
	MatchCNAMEs       []string `yaml:"match_cnames"`
	MatchIPv4Prefixes []string `yaml:"match_ipv4_prefixes"`
	MatchIPv6Prefixes []string `yaml:"match_ipv6_prefixes"`
	CNAMETTL          uint32   `yaml:"cname_ttl"`
}

var _ sequence.RecursiveExecutable = (*Fastly)(nil)

type Fastly struct {
	preferredDomain string
	matchCNAMEs     []string
	matchIPv4       []netip.Prefix
	matchIPv6       []netip.Prefix
	cnameTTL        uint32
}

func Init(_ *coremain.BP, v any) (any, error) {
	return NewFastly(v.(*Args))
}

func QuickSetup(_ sequence.BQ, s string) (any, error) {
	args := &Args{PreferredDomain: strings.TrimSpace(s)}
	return NewFastly(args)
}

func NewFastly(args *Args) (*Fastly, error) {
	if args == nil {
		args = new(Args)
	}

	preferredDomain := dns.Fqdn(args.PreferredDomain)
	if args.PreferredDomain == "" {
		preferredDomain = defaultPreferredDomain
	}

	matchCNAMEs := args.MatchCNAMEs
	if len(matchCNAMEs) == 0 {
		matchCNAMEs = defaultMatchCNAMEs
	}
	matchCNAMEs = normalizeCNAMEPatterns(matchCNAMEs)

	matchIPv4Prefixes := args.MatchIPv4Prefixes
	if len(matchIPv4Prefixes) == 0 {
		matchIPv4Prefixes = defaultMatchIPv4Prefixes
	}
	matchIPv4, err := parsePrefixes(matchIPv4Prefixes, false)
	if err != nil {
		return nil, fmt.Errorf("invalid match_ipv4_prefixes, %w", err)
	}

	matchIPv6Prefixes := args.MatchIPv6Prefixes
	if len(matchIPv6Prefixes) == 0 {
		matchIPv6Prefixes = defaultMatchIPv6Prefixes
	}
	matchIPv6, err := parsePrefixes(matchIPv6Prefixes, true)
	if err != nil {
		return nil, fmt.Errorf("invalid match_ipv6_prefixes, %w", err)
	}

	cnameTTL := args.CNAMETTL
	if cnameTTL == 0 {
		cnameTTL = defaultCNAMETTL
	}

	return &Fastly{
		preferredDomain: preferredDomain,
		matchCNAMEs:     matchCNAMEs,
		matchIPv4:       matchIPv4,
		matchIPv6:       matchIPv6,
		cnameTTL:        cnameTTL,
	}, nil
}

func (f *Fastly) Exec(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) error {
	q := qCtx.Q()
	if len(q.Question) != 1 || q.Question[0].Qclass != dns.ClassINET {
		return next.ExecNext(ctx, qCtx)
	}

	qtype := q.Question[0].Qtype
	if qtype != dns.TypeA && qtype != dns.TypeAAAA && qtype != dns.TypeCNAME {
		return next.ExecNext(ctx, qCtx)
	}
	if dns.Fqdn(q.Question[0].Name) == f.preferredDomain {
		return next.ExecNext(ctx, qCtx)
	}

	if err := next.ExecNext(ctx, qCtx); err != nil {
		return err
	}
	if !f.isFastlyResponse(qCtx.R()) {
		return nil
	}

	redirected, err := f.redirectResponse(ctx, qCtx, next)
	if err != nil {
		return err
	}
	if redirected != nil {
		qCtx.SetResponse(redirected)
	}
	return nil
}

func (f *Fastly) redirectResponse(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) (*dns.Msg, error) {
	q := qCtx.Q()
	qtype := q.Question[0].Qtype

	r := new(dns.Msg)
	r.SetReply(q)
	r.Answer = append(r.Answer, &dns.CNAME{
		Hdr: dns.RR_Header{
			Name:   q.Question[0].Name,
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    f.cnameTTL,
		},
		Target: f.preferredDomain,
	})
	if qtype == dns.TypeCNAME {
		return r, nil
	}

	targetResp, err := f.resolvePreferredDomain(ctx, qCtx, next)
	if err != nil {
		return nil, err
	}
	if targetResp == nil || targetResp.Rcode != dns.RcodeSuccess {
		return nil, nil
	}

	for _, rr := range targetResp.Answer {
		switch rr.Header().Rrtype {
		case dns.TypeCNAME, qtype:
			r.Answer = append(r.Answer, dns.Copy(rr))
		}
	}
	return r, nil
}

func (f *Fastly) resolvePreferredDomain(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) (*dns.Msg, error) {
	qCtxPreferred := qCtx.Copy()
	qCtxPreferred.SetResponse(nil)
	qCtxPreferred.Q().SetQuestion(f.preferredDomain, qCtx.Q().Question[0].Qtype)
	if err := next.ExecNext(ctx, qCtxPreferred); err != nil {
		return nil, err
	}
	return qCtxPreferred.R(), nil
}

func (f *Fastly) isFastlyResponse(r *dns.Msg) bool {
	if r == nil || r.Rcode != dns.RcodeSuccess {
		return false
	}
	for _, rr := range r.Answer {
		switch v := rr.(type) {
		case *dns.CNAME:
			if f.matchCNAME(v.Target) {
				return true
			}
		case *dns.A:
			ip, ok := addrFromIP4(v.A)
			if ok && matchPrefix(ip, f.matchIPv4) {
				return true
			}
		case *dns.AAAA:
			ip, ok := addrFromIP6(v.AAAA)
			if ok && matchPrefix(ip, f.matchIPv6) {
				return true
			}
		}
	}
	return false
}

func (f *Fastly) matchCNAME(target string) bool {
	target = dns.Fqdn(strings.ToLower(target))
	for _, suffix := range f.matchCNAMEs {
		if target == suffix || strings.HasSuffix(target, "."+suffix) {
			return true
		}
	}
	return false
}

func normalizeCNAMEPatterns(ss []string) []string {
	patterns := make([]string, 0, len(ss))
	for _, s := range ss {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		patterns = append(patterns, dns.Fqdn(strings.ToLower(s)))
	}
	return patterns
}

func parsePrefixes(ss []string, wantIPv6 bool) ([]netip.Prefix, error) {
	ps := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil {
			return nil, err
		}
		if wantIPv6 {
			if !p.Addr().Is6() || p.Addr().Is4In6() {
				return nil, fmt.Errorf("%s is not an IPv6 prefix", s)
			}
		} else if !p.Addr().Is4() {
			return nil, fmt.Errorf("%s is not an IPv4 prefix", s)
		}
		ps = append(ps, p)
	}
	return ps, nil
}

func matchPrefix(ip netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func addrFromIP4(ip net.IP) (netip.Addr, bool) {
	ip4 := ip.To4()
	if ip4 == nil {
		return netip.Addr{}, false
	}
	return netip.AddrFromSlice(ip4)
}

func addrFromIP6(ip net.IP) (netip.Addr, bool) {
	if ip.To4() != nil {
		return netip.Addr{}, false
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return netip.Addr{}, false
	}
	return netip.AddrFromSlice(ip16)
}

func genEmptyReply(q *dns.Msg) *dns.Msg {
	if q == nil {
		return nil
	}
	return dnsutils.GenEmptyReply(q, dns.RcodeSuccess)
}
