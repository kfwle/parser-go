// Package model contains the protocol-independent representation of a proxy
// configuration URL.
package model

// Protocol identifiers.
const (
	VLESS     = "vless"
	Trojan    = "trojan"
	Hysteria2 = "hysteria2"
)

// Endpoint is a parsed vless://, trojan:// or hysteria2:// URL.
type Endpoint struct {
	Protocol string
	Tag      string

	// ID is the VLESS UUID, Trojan password or Hysteria2 auth token.
	ID   string
	Host string
	Port int

	Network      string // tcp, ws, grpc, xhttp, h2, kcp, quic, httpupgrade
	Security     string // none, tls, reality
	Path         string
	HostHeader   string
	SNI          string
	Fingerprint  string
	ALPN         string
	ServiceName  string
	Flow         string
	HeaderType   string
	QUICSecurity string
	Key          string
	PublicKey    string
	ShortID      string

	AllowInsecure bool

	// Hysteria2 specific.
	Auth         string
	Insecure     bool
	Obfs         string
	ObfsPassword string
	UpMbps       string
	DownMbps     string
}

// IsHysteria2 reports whether the endpoint uses the Hysteria2 protocol.
func (e *Endpoint) IsHysteria2() bool {
	return e.Protocol == Hysteria2
}

// Label returns a short protocol label used by the CLI.
func (e *Endpoint) Label() string {
	switch e.Protocol {
	case VLESS:
		return "VLESS"
	case Trojan:
		return "TROJAN"
	case Hysteria2:
		return "HY2"
	default:
		return "UNKNOWN"
	}
}
