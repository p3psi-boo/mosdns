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
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const PluginType = "cloudflare_ech"

const (
	defaultRefreshInterval = 10 * 60
	defaultRefreshTimeout  = 5 * time.Second
	defaultECHTTL          = time.Hour
	defaultCFPreferDomain  = "cf.090227.xyz"
	defaultCFECHDomain     = "cloudflare-ech.com."
	defaultMetaECH         = "AEj+DQBEAQAgACAdd+scUi0IYFsXnUIU7ko2Nd9+F8M26pAGZVpz/KrWPgAEAAEAAWQVZWNoLXB1YmxpYy5hdG1ldGEuY29tAAA="
)

var (
	defaultCloudflareIPv4Prefixes = []string{
		"173.245.48.0/20",
		"103.21.244.0/22",
		"103.22.200.0/22",
		"103.31.4.0/22",
		"141.101.64.0/18",
		"108.162.192.0/18",
		"190.93.240.0/20",
		"188.114.96.0/20",
		"197.234.240.0/22",
		"198.41.128.0/17",
		"162.158.0.0/15",
		"104.16.0.0/13",
		"104.24.0.0/14",
		"172.64.0.0/13",
		"131.0.72.0/22",
	}
	defaultCloudflareIPv6Prefixes = []string{
		"2400:cb00::/32",
		"2606:4700::/32",
		"2803:f800::/32",
		"2405:b500::/32",
		"2405:8100::/32",
		"2a06:98c0::/29",
		"2c0f:f248::/32",
	}
	defaultALPN = []string{"h3", "h2"}
)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

type Args struct {
	IPv4 []string `yaml:"ipv4"`
	IPv6 []string `yaml:"ipv6"`

	PreferredIPDomain string   `yaml:"preferred_ip_domain"`
	PreferredIPAPIs   []string `yaml:"preferred_ip_apis"`
	RefreshInterval   int      `yaml:"refresh_interval"`

	CloudflareIPv4Prefixes []string `yaml:"cloudflare_ipv4_prefixes"`
	CloudflareIPv6Prefixes []string `yaml:"cloudflare_ipv6_prefixes"`

	CloudflareECHDomain string   `yaml:"cloudflare_ech_domain"`
	CloudflareECH       string   `yaml:"cloudflare_ech"`
	CloudflareALPN      []string `yaml:"cloudflare_alpn"`

	MetaIPv4Prefixes []string `yaml:"meta_ipv4_prefixes"`
	MetaIPv6Prefixes []string `yaml:"meta_ipv6_prefixes"`
	MetaECH          string   `yaml:"meta_ech"`
	MetaALPN         []string `yaml:"meta_alpn"`
}

var _ sequence.RecursiveExecutable = (*CloudflareECH)(nil)
var _ io.Closer = (*CloudflareECH)(nil)

type CloudflareECH struct {
	args *Args

	logger *zap.Logger
	client *http.Client

	preferredMu sync.RWMutex
	preferred4  []netip.Addr
	preferred6  []netip.Addr
	next4       uint64
	next6       uint64

	cf4   []netip.Prefix
	cf6   []netip.Prefix
	meta4 []netip.Prefix
	meta6 []netip.Prefix

	cfALPN   []string
	metaALPN []string
	metaECH  []byte

	cfECHMu  sync.RWMutex
	cfECH    []byte
	cfECHExp time.Time

	closeOnce sync.Once
	closeCh   chan struct{}
}

func Init(bp *coremain.BP, v any) (any, error) {
	return NewCloudflareECH(v.(*Args), bp.L())
}

func NewCloudflareECH(args *Args, logger *zap.Logger) (*CloudflareECH, error) {
	if args == nil {
		args = new(Args)
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	args = args.cloneWithDefaults()

	cf4, err := parsePrefixes(args.CloudflareIPv4Prefixes, false)
	if err != nil {
		return nil, fmt.Errorf("invalid cloudflare_ipv4_prefixes, %w", err)
	}
	cf6, err := parsePrefixes(args.CloudflareIPv6Prefixes, true)
	if err != nil {
		return nil, fmt.Errorf("invalid cloudflare_ipv6_prefixes, %w", err)
	}
	meta4, err := parsePrefixes(args.MetaIPv4Prefixes, false)
	if err != nil {
		return nil, fmt.Errorf("invalid meta_ipv4_prefixes, %w", err)
	}
	meta6, err := parsePrefixes(args.MetaIPv6Prefixes, true)
	if err != nil {
		return nil, fmt.Errorf("invalid meta_ipv6_prefixes, %w", err)
	}
	static4, err := parseAddrs(args.IPv4, false)
	if err != nil {
		return nil, fmt.Errorf("invalid ipv4, %w", err)
	}
	static6, err := parseAddrs(args.IPv6, true)
	if err != nil {
		return nil, fmt.Errorf("invalid ipv6, %w", err)
	}
	metaECH, err := parseECH(args.MetaECH)
	if err != nil {
		return nil, fmt.Errorf("invalid meta_ech, %w", err)
	}
	cfECH, err := parseECH(args.CloudflareECH)
	if err != nil {
		return nil, fmt.Errorf("invalid cloudflare_ech, %w", err)
	}

	p := &CloudflareECH{
		args:       args,
		logger:     logger,
		client:     &http.Client{Timeout: defaultRefreshTimeout},
		preferred4: static4,
		preferred6: static6,
		cf4:        cf4,
		cf6:        cf6,
		meta4:      meta4,
		meta6:      meta6,
		cfALPN:     append([]string(nil), args.CloudflareALPN...),
		metaALPN:   append([]string(nil), args.MetaALPN...),
		metaECH:    metaECH,
		cfECH:      cfECH,
		closeCh:    make(chan struct{}),
	}
	if len(cfECH) > 0 {
		p.cfECHExp = time.Now().Add(defaultECHTTL)
	}

	p.refreshPreferred(context.Background())
	go p.refreshLoop()
	return p, nil
}

func (a *Args) cloneWithDefaults() *Args {
	c := *a
	if c.RefreshInterval <= 0 {
		c.RefreshInterval = defaultRefreshInterval
	}
	if c.PreferredIPDomain == "" && len(c.PreferredIPAPIs) == 0 && len(c.IPv4)+len(c.IPv6) == 0 {
		c.PreferredIPDomain = defaultCFPreferDomain
	}
	if len(c.CloudflareIPv4Prefixes) == 0 {
		c.CloudflareIPv4Prefixes = append([]string(nil), defaultCloudflareIPv4Prefixes...)
	}
	if len(c.CloudflareIPv6Prefixes) == 0 {
		c.CloudflareIPv6Prefixes = append([]string(nil), defaultCloudflareIPv6Prefixes...)
	}
	if c.CloudflareECHDomain == "" {
		c.CloudflareECHDomain = defaultCFECHDomain
	}
	c.CloudflareECHDomain = dns.Fqdn(c.CloudflareECHDomain)
	if len(c.CloudflareALPN) == 0 {
		c.CloudflareALPN = append([]string(nil), defaultALPN...)
	}
	if c.MetaECH == "" {
		c.MetaECH = defaultMetaECH
	}
	if len(c.MetaALPN) == 0 {
		c.MetaALPN = append([]string(nil), defaultALPN...)
	}
	return &c
}

func (p *CloudflareECH) Close() error {
	p.closeOnce.Do(func() {
		close(p.closeCh)
	})
	return nil
}

func (p *CloudflareECH) Exec(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) error {
	q := qCtx.Q()
	if len(q.Question) != 1 || q.Question[0].Qclass != dns.ClassINET {
		return next.ExecNext(ctx, qCtx)
	}

	qtype := q.Question[0].Qtype
	if qtype != dns.TypeA && qtype != dns.TypeAAAA && qtype != dns.TypeHTTPS {
		return next.ExecNext(ctx, qCtx)
	}

	if err := next.ExecNext(ctx, qCtx); err != nil {
		return err
	}

	switch qtype {
	case dns.TypeA, dns.TypeAAAA:
		p.rewriteAddressResponse(qCtx.R())
	case dns.TypeHTTPS:
		if err := p.rewriteHTTPSResponse(ctx, qCtx, next); err != nil {
			return err
		}
	}
	return nil
}

func (p *CloudflareECH) rewriteAddressResponse(r *dns.Msg) {
	if r == nil {
		return
	}
	for _, rr := range r.Answer {
		switch v := rr.(type) {
		case *dns.A:
			ip, ok := addrFromIP4(v.A)
			if !ok || !matchPrefix(ip, p.cf4) {
				continue
			}
			if preferred, ok := p.nextPreferred(false); ok {
				v.A = ipToNetIP(preferred)
			}
		case *dns.AAAA:
			ip, ok := addrFromIP6(v.AAAA)
			if !ok || !matchPrefix(ip, p.cf6) {
				continue
			}
			if preferred, ok := p.nextPreferred(true); ok {
				v.AAAA = ipToNetIP(preferred)
			}
		}
	}
}

func (p *CloudflareECH) rewriteHTTPSResponse(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) error {
	r := qCtx.R()
	if r == nil {
		return nil
	}

	service := p.classifyHTTPSResponse(r)
	if service == serviceNone {
		var err error
		service, err = p.classifyByAddressQueries(ctx, qCtx, next)
		if err != nil {
			return err
		}
	}

	switch service {
	case serviceCloudflare:
		ech, err := p.cloudflareECH(ctx, qCtx, next)
		if err != nil {
			p.logger.Warn("failed to get cloudflare ech", qCtx.InfoField(), zap.Error(err))
			return nil
		}
		rewriteHTTPSRecords(r, p.cfALPN, ech)
	case serviceMeta:
		if len(p.metaECH) > 0 {
			rewriteHTTPSRecords(r, p.metaALPN, p.metaECH)
		}
	}
	return nil
}

type serviceType uint8

const (
	serviceNone serviceType = iota
	serviceCloudflare
	serviceMeta
)

func (p *CloudflareECH) classifyHTTPSResponse(r *dns.Msg) serviceType {
	for _, rr := range r.Answer {
		httpsRR, ok := rr.(*dns.HTTPS)
		if !ok {
			continue
		}
		for _, kv := range httpsRR.Value {
			switch v := kv.(type) {
			case *dns.SVCBIPv4Hint:
				if service := p.classifyIPs(v.Hint); service != serviceNone {
					return service
				}
			case *dns.SVCBIPv6Hint:
				if service := p.classifyIPs(v.Hint); service != serviceNone {
					return service
				}
			}
		}
	}
	return serviceNone
}

func (p *CloudflareECH) classifyByAddressQueries(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) (serviceType, error) {
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		qCtxAddr := qCtx.Copy()
		qCtxAddr.SetResponse(nil)
		qCtxAddr.Q().Question[0].Qtype = qtype
		if err := next.ExecNext(ctx, qCtxAddr); err != nil {
			return serviceNone, err
		}
		if service := p.classifyAddressResponse(qCtxAddr.R()); service != serviceNone {
			return service, nil
		}
	}
	return serviceNone, nil
}

func (p *CloudflareECH) classifyAddressResponse(r *dns.Msg) serviceType {
	if r == nil {
		return serviceNone
	}
	for _, rr := range r.Answer {
		switch v := rr.(type) {
		case *dns.A:
			ip, ok := addrFromIP4(v.A)
			if ok {
				if matchPrefix(ip, p.cf4) {
					return serviceCloudflare
				}
				if matchPrefix(ip, p.meta4) {
					return serviceMeta
				}
			}
		case *dns.AAAA:
			ip, ok := addrFromIP6(v.AAAA)
			if ok {
				if matchPrefix(ip, p.cf6) {
					return serviceCloudflare
				}
				if matchPrefix(ip, p.meta6) {
					return serviceMeta
				}
			}
		}
	}
	return serviceNone
}

func (p *CloudflareECH) classifyIPs(ips []net.IP) serviceType {
	for _, ip := range ips {
		addr, ok := addrFromIP4(ip)
		if !ok {
			addr, ok = addrFromIP6(ip)
		}
		if !ok {
			continue
		}
		if matchPrefix(addr, p.cf4) || matchPrefix(addr, p.cf6) {
			return serviceCloudflare
		}
		if matchPrefix(addr, p.meta4) || matchPrefix(addr, p.meta6) {
			return serviceMeta
		}
	}
	return serviceNone
}

func (p *CloudflareECH) cloudflareECH(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) ([]byte, error) {
	p.cfECHMu.RLock()
	if len(p.cfECH) > 0 && time.Now().Before(p.cfECHExp) {
		ech := append([]byte(nil), p.cfECH...)
		p.cfECHMu.RUnlock()
		return ech, nil
	}
	p.cfECHMu.RUnlock()

	qCtxECH := qCtx.Copy()
	qCtxECH.SetResponse(nil)
	qCtxECH.Q().SetQuestion(p.args.CloudflareECHDomain, dns.TypeHTTPS)
	if err := next.ExecNext(ctx, qCtxECH); err != nil {
		return nil, err
	}
	ech := extractECH(qCtxECH.R())
	if len(ech) == 0 {
		return nil, errors.New("cloudflare ech response has no ech config")
	}

	p.cfECHMu.Lock()
	p.cfECH = append([]byte(nil), ech...)
	p.cfECHExp = time.Now().Add(defaultECHTTL)
	p.cfECHMu.Unlock()
	return ech, nil
}

func rewriteHTTPSRecords(r *dns.Msg, alpn []string, ech []byte) {
	if r == nil || len(ech) == 0 {
		return
	}
	for _, rr := range r.Answer {
		httpsRR, ok := rr.(*dns.HTTPS)
		if !ok {
			continue
		}
		rewriteSVCBValues(&httpsRR.SVCB, alpn, ech)
	}
}

func rewriteSVCBValues(svcb *dns.SVCB, alpn []string, ech []byte) {
	if svcb == nil || svcb.Priority == 0 {
		return
	}

	values := make([]dns.SVCBKeyValue, 0, len(svcb.Value)+2)
	addedALPN := len(alpn) == 0
	addedECH := false
	for _, kv := range svcb.Value {
		switch kv.Key() {
		case dns.SVCB_ALPN:
			if !addedALPN {
				values = append(values, &dns.SVCBAlpn{Alpn: append([]string(nil), alpn...)})
				addedALPN = true
			}
		case dns.SVCB_ECHCONFIG:
			if !addedECH {
				values = append(values, &dns.SVCBECHConfig{ECH: append([]byte(nil), ech...)})
				addedECH = true
			}
		default:
			values = append(values, kv)
		}
	}
	if !addedALPN {
		values = append(values, &dns.SVCBAlpn{Alpn: append([]string(nil), alpn...)})
	}
	if !addedECH {
		values = append(values, &dns.SVCBECHConfig{ECH: append([]byte(nil), ech...)})
	}
	svcb.Value = values
}

func extractECH(r *dns.Msg) []byte {
	if r == nil {
		return nil
	}
	for _, rr := range r.Answer {
		httpsRR, ok := rr.(*dns.HTTPS)
		if !ok {
			continue
		}
		for _, kv := range httpsRR.Value {
			if ech, ok := kv.(*dns.SVCBECHConfig); ok && len(ech.ECH) > 0 {
				return append([]byte(nil), ech.ECH...)
			}
		}
	}
	return nil
}

func (p *CloudflareECH) nextPreferred(ipv6 bool) (netip.Addr, bool) {
	p.preferredMu.Lock()
	defer p.preferredMu.Unlock()

	if ipv6 {
		if len(p.preferred6) == 0 {
			return netip.Addr{}, false
		}
		i := p.next6 % uint64(len(p.preferred6))
		p.next6++
		return p.preferred6[i], true
	}

	if len(p.preferred4) == 0 {
		return netip.Addr{}, false
	}
	i := p.next4 % uint64(len(p.preferred4))
	p.next4++
	return p.preferred4[i], true
}

func (p *CloudflareECH) refreshLoop() {
	ticker := time.NewTicker(time.Duration(p.args.RefreshInterval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.refreshPreferred(context.Background())
		case <-p.closeCh:
			return
		}
	}
}

func (p *CloudflareECH) refreshPreferred(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, defaultRefreshTimeout)
	defer cancel()

	ipv4 := make([]netip.Addr, 0)
	ipv6 := make([]netip.Addr, 0)

	static4, _ := parseAddrs(p.args.IPv4, false)
	static6, _ := parseAddrs(p.args.IPv6, true)
	ipv4 = append(ipv4, static4...)
	ipv6 = append(ipv6, static6...)

	if p.args.PreferredIPDomain != "" {
		addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", p.args.PreferredIPDomain)
		if err != nil {
			p.logger.Warn("failed to resolve preferred ip domain", zap.String("domain", p.args.PreferredIPDomain), zap.Error(err))
		} else {
			for _, addr := range addrs {
				if addr.Is4() {
					ipv4 = append(ipv4, addr)
				} else if addr.Is6() && !addr.Is4In6() {
					ipv6 = append(ipv6, addr)
				}
			}
		}
	}

	for _, api := range p.args.PreferredIPAPIs {
		addrs, err := p.fetchPreferredAPI(ctx, api)
		if err != nil {
			p.logger.Warn("failed to fetch preferred ip api", zap.String("url", api), zap.Error(err))
			continue
		}
		for _, addr := range addrs {
			if addr.Is4() {
				ipv4 = append(ipv4, addr)
			} else if addr.Is6() && !addr.Is4In6() {
				ipv6 = append(ipv6, addr)
			}
		}
	}

	ipv4 = uniqueAddrs(ipv4)
	ipv6 = uniqueAddrs(ipv6)
	if len(ipv4)+len(ipv6) == 0 {
		return
	}

	p.preferredMu.Lock()
	p.preferred4 = ipv4
	p.preferred6 = ipv6
	p.next4 = uint64(rand.IntN(max(1, len(ipv4))))
	p.next6 = uint64(rand.IntN(max(1, len(ipv6))))
	p.preferredMu.Unlock()
	p.logger.Info("preferred cloudflare ips refreshed", zap.Int("ipv4", len(ipv4)), zap.Int("ipv6", len(ipv6)))
}

func (p *CloudflareECH) fetchPreferredAPI(ctx context.Context, url string) ([]netip.Addr, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return parseAddrsFromText(string(b)), nil
}

func parseAddrsFromText(s string) []netip.Addr {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', ',', '"', '\'', '[', ']', '{', '}', '(', ')', '<', '>', '|', ';':
			return true
		default:
			return false
		}
	})
	addrs := make([]netip.Addr, 0, len(fields))
	for _, field := range fields {
		field = strings.Trim(field, ".")
		addr, err := netip.ParseAddr(field)
		if err == nil {
			addrs = append(addrs, addr)
		}
	}
	return uniqueAddrs(addrs)
}

func parsePrefixes(ss []string, wantIPv6 bool) ([]netip.Prefix, error) {
	ps := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		if strings.TrimSpace(s) == "" {
			continue
		}
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

func parseAddrs(ss []string, wantIPv6 bool) ([]netip.Addr, error) {
	addrs := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		if strings.TrimSpace(s) == "" {
			continue
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			return nil, err
		}
		if wantIPv6 {
			if !addr.Is6() || addr.Is4In6() {
				return nil, fmt.Errorf("%s is not an IPv6 address", s)
			}
		} else if !addr.Is4() {
			return nil, fmt.Errorf("%s is not an IPv4 address", s)
		}
		addrs = append(addrs, addr)
	}
	return uniqueAddrs(addrs), nil
}

func parseECH(s string) ([]byte, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	s = strings.TrimSpace(s)
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, errors.New("bad base64 ech")
}

func uniqueAddrs(in []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(in))
	seen := make(map[netip.Addr]struct{}, len(in))
	for _, addr := range in {
		if !addr.IsValid() {
			continue
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	return out
}

func matchPrefix(addr netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(addr) {
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

func ipToNetIP(addr netip.Addr) net.IP {
	return append(net.IP(nil), addr.AsSlice()...)
}
