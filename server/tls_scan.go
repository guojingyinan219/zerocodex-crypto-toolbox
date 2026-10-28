package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type check struct {
	Level  string `json:"level"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

type certificate struct {
	Subject            string   `json:"subject"`
	Issuer             string   `json:"issuer"`
	NotBefore          string   `json:"notBefore"`
	NotAfter           string   `json:"notAfter"`
	SerialNumber       string   `json:"serialNumber"`
	DNSNames           []string `json:"dnsNames"`
	PublicKeyAlgorithm string   `json:"publicKeyAlgorithm"`
	PublicKeySize      int      `json:"publicKeySize"`
	SignatureAlgorithm string   `json:"signatureAlgorithm"`
	FingerprintSHA256  string   `json:"fingerprintSha256"`
}

type validation struct {
	Trusted bool   `json:"trusted"`
	Message string `json:"message"`
}

type protocolProbe struct {
	Name        string `json:"name"`
	Supported   bool   `json:"supported"`
	CipherSuite string `json:"cipherSuite"`
	ALPN        string `json:"alpn"`
	Message     string `json:"message"`
}

type dnsProbe struct {
	Addresses []string `json:"addresses"`
	CAA       []string `json:"caa"`
	Message   string   `json:"message"`
}

type webProbe struct {
	Reachable   bool   `json:"reachable"`
	StatusCode  int    `json:"statusCode"`
	HTTPVersion string `json:"httpVersion"`
	ALPN        string `json:"alpn"`
	HSTS        string `json:"hsts"`
	Message     string `json:"message"`
}

type certificateVariant struct {
	Supported          bool   `json:"supported"`
	PublicKeyAlgorithm string `json:"publicKeyAlgorithm"`
	Subject            string `json:"subject"`
	FingerprintSHA256  string `json:"fingerprintSha256"`
	CipherSuite        string `json:"cipherSuite"`
}

type dualCertificateProbe struct {
	RSA     certificateVariant `json:"rsa"`
	ECC     certificateVariant `json:"ecc"`
	Dual    bool               `json:"dual"`
	Message string             `json:"message"`
}

type gmProbe struct {
	Available        bool   `json:"available"`
	Attempted        bool   `json:"attempted"`
	Supported        bool   `json:"supported"`
	Protocol         string `json:"protocol"`
	CipherSuite      string `json:"cipherSuite"`
	CertificateCount int    `json:"certificateCount"`
	DualCertificate  bool   `json:"dualCertificate"`
	Message          string `json:"message"`
}

type report struct {
	Host            string               `json:"host"`
	Address         string               `json:"address"`
	Protocol        string               `json:"protocol"`
	CipherSuite     string               `json:"cipherSuite"`
	Certificate     certificate          `json:"certificate"`
	Chain           []certificate        `json:"chain"`
	Validation      validation           `json:"validation"`
	OCSPStapled     bool                 `json:"ocspStapled"`
	AlgorithmFamily string               `json:"algorithmFamily"`
	Checks          []check              `json:"checks"`
	RiskChecks      []check              `json:"riskChecks"`
	Protocols       []protocolProbe      `json:"protocols"`
	DNS             dnsProbe             `json:"dns"`
	Web             webProbe             `json:"web"`
	DualCertificate dualCertificateProbe `json:"dualCertificate"`
	GMProbe         gmProbe              `json:"gmProbe"`
}

type handshakeResult struct {
	state tls.ConnectionState
	err   error
}

var hostnamePattern = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"), netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff00::/8"),
}

func scan(ctx context.Context, rawHost string) (report, error) {
	host, err := normalizeHost(rawHost)
	if err != nil {
		return report{}, err
	}
	addresses, err := resolvePublic(ctx, host)
	if err != nil {
		return report{}, err
	}
	address := addresses[0]

	var standard handshakeResult
	var protocols []protocolProbe
	var dnsResult dnsProbe
	var web webProbe
	var dual dualCertificateProbe
	var gm gmProbe
	var weakCipher bool
	var wait sync.WaitGroup
	wait.Add(7)
	go func() { defer wait.Done(); standard = tlsHandshake(ctx, host, address, 0, 0, nil) }()
	go func() { defer wait.Done(); protocols = scanProtocols(ctx, host, address) }()
	go func() { defer wait.Done(); dnsResult = scanDNS(ctx, host, addresses) }()
	go func() { defer wait.Done(); web = scanWeb(ctx, host, address) }()
	go func() { defer wait.Done(); dual = scanDualCertificate(ctx, host, address) }()
	go func() { defer wait.Done(); gm = scanGM(ctx, host, address) }()
	go func() { defer wait.Done(); weakCipher = scanWeakCiphers(ctx, host, address) }()
	wait.Wait()

	if standard.err != nil {
		return report{}, fmt.Errorf("无法建立标准 TLS 连接：%v", friendlyNetworkError(standard.err))
	}
	if len(standard.state.PeerCertificates) == 0 {
		return report{}, errors.New("服务器未返回证书")
	}

	leaf := standard.state.PeerCertificates[0]
	chain := make([]certificate, 0, len(standard.state.PeerCertificates))
	for _, item := range standard.state.PeerCertificates {
		chain = append(chain, describeCertificate(item))
	}
	verified, validationMessage := verifyCertificate(host, standard.state.PeerCertificates)
	family := "standard"
	if gm.Supported {
		family = "dual"
	}

	result := report{
		Host: host, Address: address, Protocol: tlsVersionName(standard.state.Version),
		CipherSuite: tls.CipherSuiteName(standard.state.CipherSuite), Certificate: describeCertificate(leaf),
		Chain: chain, Validation: validation{Trusted: verified, Message: validationMessage},
		OCSPStapled: len(standard.state.OCSPResponse) > 0, AlgorithmFamily: family,
		Protocols: protocols, DNS: dnsResult, Web: web, DualCertificate: dual, GMProbe: gm,
	}
	result.Checks = buildChecks(result)
	result.RiskChecks = buildRiskChecks(result, weakCipher)
	return result, nil
}

func normalizeHost(value string) (string, error) {
	value = strings.TrimSpace(strings.TrimSuffix(value, "."))
	if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" {
		if parsed.Port() != "" && parsed.Port() != "443" {
			return "", errors.New("仅支持检测 443 端口")
		}
		value = parsed.Hostname()
	}
	value = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(value, ".")))
	if len(value) > 253 || net.ParseIP(value) != nil || !hostnamePattern.MatchString(value) || strings.Contains(value, "..") {
		return "", errors.New("请输入公开网站域名，例如 example.com；不支持 IP、端口或内网地址")
	}
	return value, nil
}

func resolvePublic(ctx context.Context, host string) ([]string, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	items, err := net.DefaultResolver.LookupIPAddr(lookupCtx, host)
	if err != nil || len(items) == 0 {
		return nil, fmt.Errorf("域名解析失败：%v", friendlyNetworkError(err))
	}
	seen := make(map[string]bool)
	addresses := make([]string, 0, len(items))
	for _, item := range items {
		if !isPublicIP(item.IP) {
			return nil, errors.New("域名解析到内网、保留或不可路由地址，已拒绝检测")
		}
		value := item.IP.String()
		if !seen[value] {
			seen[value] = true
			addresses = append(addresses, value)
		}
	}
	sort.Strings(addresses)
	return addresses, nil
}

func isPublicIP(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() {
		return false
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func tlsHandshake(ctx context.Context, host, address string, minVersion, maxVersion uint16, cipherSuites []uint16) handshakeResult {
	dialer := &net.Dialer{Timeout: 4 * time.Second}
	dialCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	raw, err := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(address, "443"))
	if err != nil {
		return handshakeResult{err: err}
	}
	defer raw.Close()
	config := &tls.Config{
		ServerName: host, InsecureSkipVerify: true, MinVersion: minVersion, MaxVersion: maxVersion,
		CipherSuites: cipherSuites, NextProtos: []string{"h2", "http/1.1"},
	}
	connection := tls.Client(raw, config)
	if err := connection.HandshakeContext(dialCtx); err != nil {
		return handshakeResult{err: err}
	}
	return handshakeResult{state: connection.ConnectionState()}
}

func scanProtocols(ctx context.Context, host, address string) []protocolProbe {
	versions := []struct {
		name    string
		version uint16
	}{
		{"TLS 1.0", tls.VersionTLS10}, {"TLS 1.1", tls.VersionTLS11},
		{"TLS 1.2", tls.VersionTLS12}, {"TLS 1.3", tls.VersionTLS13},
	}
	results := make([]protocolProbe, len(versions))
	var wait sync.WaitGroup
	for index, item := range versions {
		wait.Add(1)
		go func(index int, name string, version uint16) {
			defer wait.Done()
			probe := tlsHandshake(ctx, host, address, version, version, nil)
			results[index] = protocolProbe{Name: name, Supported: probe.err == nil}
			if probe.err == nil {
				results[index].CipherSuite = tls.CipherSuiteName(probe.state.CipherSuite)
				results[index].ALPN = probe.state.NegotiatedProtocol
				results[index].Message = "握手成功"
			} else {
				results[index].Message = "未协商成功"
			}
		}(index, item.name, item.version)
	}
	wait.Wait()
	return results
}

func scanDNS(ctx context.Context, host string, addresses []string) dnsProbe {
	result := dnsProbe{Addresses: addresses, CAA: []string{}}
	queryCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	endpoint := "https://cloudflare-dns.com/dns-query?name=" + url.QueryEscape(host) + "&type=CAA"
	request, _ := http.NewRequestWithContext(queryCtx, http.MethodGet, endpoint, nil)
	request.Header.Set("Accept", "application/dns-json")
	response, err := (&http.Client{Timeout: 4 * time.Second}).Do(request)
	if err != nil {
		result.Message = "IP 解析成功，CAA 查询失败"
		return result
	}
	defer response.Body.Close()
	var payload struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 64*1024)).Decode(&payload) != nil {
		result.Message = "IP 解析成功，CAA 查询失败"
		return result
	}
	for _, answer := range payload.Answer {
		if answer.Type == 257 && answer.Data != "" {
			result.CAA = append(result.CAA, answer.Data)
		}
	}
	result.Message = "DNS 查询完成"
	if len(result.CAA) == 0 {
		result.Message = "未发现 CAA 记录"
	}
	return result
}

func scanWeb(ctx context.Context, host, address string) webProbe {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		Proxy: nil, ForceAttemptHTTP2: true,
		DialContext: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(dialCtx, network, net.JoinHostPort(address, "443"))
		},
		TLSClientConfig:     &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 5 * time.Second,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport, Timeout: 6 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/", nil)
	response, err := client.Do(request)
	if err != nil {
		return webProbe{Message: "HTTPS 请求失败：" + friendlyNetworkError(err).Error()}
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 32*1024))
	result := webProbe{Reachable: true, StatusCode: response.StatusCode, HTTPVersion: response.Proto, HSTS: response.Header.Get("Strict-Transport-Security"), Message: "HTTPS 响应正常"}
	if response.TLS != nil {
		result.ALPN = response.TLS.NegotiatedProtocol
	}
	return result
}

func scanDualCertificate(ctx context.Context, host, address string) dualCertificateProbe {
	rsaSuites := []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384}
	eccSuites := []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384}
	var rsaResult, eccResult handshakeResult
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		rsaResult = tlsHandshake(ctx, host, address, tls.VersionTLS12, tls.VersionTLS12, rsaSuites)
	}()
	go func() {
		defer wait.Done()
		eccResult = tlsHandshake(ctx, host, address, tls.VersionTLS12, tls.VersionTLS12, eccSuites)
	}()
	wait.Wait()
	result := dualCertificateProbe{RSA: describeVariant(rsaResult), ECC: describeVariant(eccResult)}
	result.Dual = result.RSA.Supported && result.ECC.Supported && result.RSA.FingerprintSHA256 != result.ECC.FingerprintSHA256
	switch {
	case result.Dual:
		result.Message = "检测到独立的 RSA 与 ECC 证书"
	case result.RSA.Supported && result.ECC.Supported:
		result.Message = "RSA 与 ECC 套件均可协商，但返回了同一张证书"
	case result.RSA.Supported:
		result.Message = "检测到 RSA 证书能力"
	case result.ECC.Supported:
		result.Message = "检测到 ECC 证书能力"
	default:
		result.Message = "未在 TLS 1.2 探测中确认 RSA/ECC 证书能力"
	}
	return result
}

func describeVariant(probe handshakeResult) certificateVariant {
	if probe.err != nil || len(probe.state.PeerCertificates) == 0 {
		return certificateVariant{}
	}
	item := describeCertificate(probe.state.PeerCertificates[0])
	return certificateVariant{Supported: true, PublicKeyAlgorithm: item.PublicKeyAlgorithm, Subject: item.Subject, FingerprintSHA256: item.FingerprintSHA256, CipherSuite: tls.CipherSuiteName(probe.state.CipherSuite)}
}

func scanWeakCiphers(ctx context.Context, host, address string) bool {
	weakSuites := []uint16{0x0005, 0x000A, 0xC011, 0xC012}
	probe := tlsHandshake(ctx, host, address, tls.VersionTLS10, tls.VersionTLS12, weakSuites)
	return probe.err == nil
}

func scanGM(ctx context.Context, host, address string) gmProbe {
	binary := strings.TrimSpace(os.Getenv("GMSSL_BIN"))
	if binary == "" {
		for _, candidate := range []string{"tongsuo", "gmssl"} {
			if path, err := exec.LookPath(candidate); err == nil {
				binary = path
				break
			}
		}
	}
	if binary == "" {
		return gmProbe{Message: "服务端未安装 GmSSL/Tongsuo，未执行 TLCP 探测"}
	}
	probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	command := exec.CommandContext(probeCtx, binary, "s_client", "-connect", net.JoinHostPort(address, "443"), "-servername", host, "-tlcp")
	command.Stdin = strings.NewReader("")
	output, err := command.CombinedOutput()
	text := string(output)
	result := gmProbe{Available: true, Attempted: true}
	if probeCtx.Err() != nil {
		result.Message = "TLCP 探针执行超时"
		return result
	}
	result.CertificateCount = strings.Count(text, "BEGIN CERTIFICATE")
	result.DualCertificate = result.CertificateCount >= 2
	result.Protocol = firstMatch(text, `(?im)^\s*Protocol\s*:\s*([^\r\n]+)`)
	result.CipherSuite = firstMatch(text, `(?im)^\s*Cipher(?:\s+is|\s*:)\s*([^\r\n]+)`)
	result.Supported = err == nil && (result.CertificateCount > 0 || result.Protocol != "" || result.CipherSuite != "")
	if result.Supported {
		result.Message = "TLCP 握手成功"
		if !result.DualCertificate {
			result.Message = "TLCP 握手成功，但未确认完整双证书"
		}
	} else {
		result.Message = "已执行 TLCP 探测，未协商成功"
	}
	return result
}

func firstMatch(value, pattern string) string {
	match := regexp.MustCompile(pattern).FindStringSubmatch(value)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}

func describeCertificate(item *x509.Certificate) certificate {
	digest := sha256.Sum256(item.Raw)
	return certificate{
		Subject: item.Subject.String(), Issuer: item.Issuer.String(),
		NotBefore: item.NotBefore.Local().Format("2006-01-02 15:04:05"), NotAfter: item.NotAfter.Local().Format("2006-01-02 15:04:05"),
		SerialNumber: strings.ToUpper(item.SerialNumber.Text(16)), DNSNames: append([]string(nil), item.DNSNames...),
		PublicKeyAlgorithm: item.PublicKeyAlgorithm.String(), PublicKeySize: publicKeySize(item.PublicKey),
		SignatureAlgorithm: item.SignatureAlgorithm.String(), FingerprintSHA256: strings.ToUpper(hex.EncodeToString(digest[:])),
	}
}

func publicKeySize(key any) int {
	switch value := key.(type) {
	case *rsa.PublicKey:
		return value.N.BitLen()
	case *ecdsa.PublicKey:
		return value.Curve.Params().BitSize
	case ed25519.PublicKey:
		return len(value) * 8
	default:
		return 0
	}
}

func verifyCertificate(host string, certificates []*x509.Certificate) (bool, string) {
	intermediates := x509.NewCertPool()
	for _, item := range certificates[1:] {
		intermediates.AddCert(item)
	}
	_, err := certificates[0].Verify(x509.VerifyOptions{DNSName: host, Intermediates: intermediates})
	if err == nil {
		return true, "证书链可信、域名匹配且在有效期内"
	}
	return false, "验证失败：" + err.Error()
}

func buildChecks(value report) []check {
	keyDetail := value.Certificate.PublicKeyAlgorithm
	if value.Certificate.PublicKeySize > 0 {
		keyDetail += fmt.Sprintf(" %d bit", value.Certificate.PublicKeySize)
	}
	checks := []check{
		levelCheck(value.Validation.Trusted, "证书链与域名", value.Validation.Message),
		levelCheck(time.Now().Before(timeFromCertificate(value.Certificate.NotAfter)), "证书有效期", "有效期至 "+value.Certificate.NotAfter),
		levelCheck(value.Certificate.PublicKeySize == 0 || value.Certificate.PublicKeySize >= 2048 || !strings.EqualFold(value.Certificate.PublicKeyAlgorithm, "RSA"), "公钥强度", keyDetail),
	}
	if value.GMProbe.Supported {
		checks = append(checks, levelCheck(value.GMProbe.DualCertificate, "国密双证书", value.GMProbe.Message))
	} else {
		checks = append(checks, check{Level: "warn", Title: "国密 TLCP", Detail: value.GMProbe.Message})
	}
	return checks
}

func buildRiskChecks(value report, weakCipher bool) []check {
	legacy := protocolSupported(value.Protocols, "TLS 1.0") || protocolSupported(value.Protocols, "TLS 1.1")
	signature := strings.ToUpper(value.Certificate.SignatureAlgorithm)
	weakSignature := strings.Contains(signature, "SHA1") || strings.Contains(signature, "MD5")
	weakRSA := strings.EqualFold(value.Certificate.PublicKeyAlgorithm, "RSA") && value.Certificate.PublicKeySize > 0 && value.Certificate.PublicKeySize < 2048
	return []check{
		inverseCheck(legacy, "旧版 TLS 协议", "TLS 1.0 / 1.1 不应继续启用", "未检测到 TLS 1.0 / 1.1"),
		inverseCheck(weakCipher, "弱密码套件", "服务器接受 RC4 或 3DES 类弱套件", "未协商到 RC4 / 3DES 弱套件"),
		inverseCheck(weakSignature, "弱证书签名", "证书使用 SHA-1 或 MD5 签名", "未发现 SHA-1 / MD5 证书签名"),
		inverseCheck(weakRSA, "RSA 密钥长度", fmt.Sprintf("RSA 密钥仅 %d bit", value.Certificate.PublicKeySize), "RSA 密钥长度满足 2048 bit 要求，或使用非 RSA 公钥"),
		levelCheck(value.Web.HSTS != "", "HSTS", map[bool]string{true: "已返回 Strict-Transport-Security", false: "未发现 Strict-Transport-Security"}[value.Web.HSTS != ""]),
		levelCheck(len(value.DNS.CAA) > 0, "CAA", map[bool]string{true: "已配置证书颁发机构限制", false: "未发现 CAA 记录"}[len(value.DNS.CAA) > 0]),
		levelCheck(value.OCSPStapled, "OCSP 装订", map[bool]string{true: "TLS 握手携带 OCSP 响应", false: "TLS 握手未携带 OCSP 响应"}[value.OCSPStapled]),
		{Level: "warn", Title: "主动漏洞探测范围", Detail: "本次未发送 Heartbleed、CRIME、DROWN、FREAK、Logjam、POODLE 等利用载荷，不能据此判断这些漏洞不存在。"},
	}
}

func levelCheck(ok bool, title, detail string) check {
	level := "pass"
	if !ok {
		level = "warn"
	}
	return check{Level: level, Title: title, Detail: detail}
}

func inverseCheck(risk bool, title, riskDetail, safeDetail string) check {
	if risk {
		return check{Level: "fail", Title: title, Detail: riskDetail}
	}
	return check{Level: "pass", Title: title, Detail: safeDetail}
}

func protocolSupported(items []protocolProbe, name string) bool {
	for _, item := range items {
		if item.Name == name {
			return item.Supported
		}
	}
	return false
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "未知"
	}
}

func timeFromCertificate(value string) time.Time {
	parsed, _ := time.ParseInLocation("2006-01-02 15:04:05", value, time.Local)
	return parsed
}

func friendlyNetworkError(err error) error {
	if err == nil {
		return errors.New("未知错误")
	}
	if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
		return errors.New("连接超时")
	}
	return err
}
