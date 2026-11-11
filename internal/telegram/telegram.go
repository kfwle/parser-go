// Package telegram parses public Telegram channels through their web preview
// (https://t.me/s/<channel>). It needs no API credentials or MTProto session,
// which keeps the Go port fully self-contained.
package telegram

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/html"

	"github.com/kfwle/parser-go/internal/config"
	"github.com/kfwle/parser-go/internal/extract"
	"github.com/kfwle/parser-go/internal/fetch"
	"github.com/kfwle/parser-go/internal/happ"
	"github.com/kfwle/parser-go/internal/logx"
)

// Stats summarises one Telegram run.
type Stats struct {
	Channels   int
	Messages   int
	Files      int
	Base64     int
	JSON       int
	YAML       int
	Happ       int
	Configs    int
	Sources    int
	Downloaded int
}

// Result holds everything found in Telegram channels.
type Result struct {
	VLESS   map[string]struct{}
	Trojan  map[string]struct{}
	Hy2     map[string]struct{}
	Sources map[string]struct{}
	Stats   Stats
}

func newResult() Result {
	return Result{
		VLESS:   make(map[string]struct{}),
		Trojan:  make(map[string]struct{}),
		Hy2:     make(map[string]struct{}),
		Sources: make(map[string]struct{}),
	}
}

// Parser reads public channels.
type Parser struct {
	cfg   config.Config
	limit int
}

// New creates a Telegram web parser.
func New(cfg config.Config) *Parser {
	return &Parser{cfg: cfg, limit: cfg.TGMessagesLimit}
}

// ParseChannels processes every channel link and merges results.
func (p *Parser) ParseChannels(ctx context.Context, links []string) Result {
	total := newResult()
	if p.cfg.DownloadFilesTG {
		logx.Verbosef("  Telegram: скачивание документов недоступно в web-режиме, пропускаю\n")
	}
	for idx, link := range links {
		if ctx.Err() != nil {
			break
		}
		name, ok := ChannelName(link)
		if !ok {
			logx.Printf("[%d/%d] некорректная ссылка: %s\n", idx+1, len(links), link)
			continue
		}
		logx.Printf("\n[%d/%d] https://t.me/%s\n", idx+1, len(links), name)
		res, err := p.parseChannel(ctx, name)
		if err != nil {
			logx.Printf("  Ошибка: %v\n", err)
			continue
		}
		total.Stats.Channels++
		total.Stats.Messages += res.Stats.Messages
		total.Stats.Base64 += res.Stats.Base64
		total.Stats.JSON += res.Stats.JSON
		total.Stats.YAML += res.Stats.YAML
		total.Stats.Happ += res.Stats.Happ
		mergeSet(total.VLESS, res.VLESS)
		mergeSet(total.Trojan, res.Trojan)
		mergeSet(total.Hy2, res.Hy2)
		mergeSet(total.Sources, res.Sources)
	}
	total.Stats.Configs = len(total.VLESS) + len(total.Trojan) + len(total.Hy2)
	total.Stats.Sources = len(total.Sources)
	return total
}

type channelResult struct {
	Stats Stats
	Result
}

func (p *Parser) parseChannel(ctx context.Context, name string) (channelResult, error) {
	out := channelResult{Result: newResult()}
	base := "https://t.me/s/" + url.PathEscape(name)
	pageURL := base
	minID := int64(0)
	seenIDs := make(map[int64]struct{})
	options := extract.Options{
		VLESS:     p.cfg.SaveVlessTG,
		Trojan:    p.cfg.SaveTrojanTG,
		Hysteria2: p.cfg.SaveHy2TG,
		Base64:    p.cfg.DecodeBase64TG,
		JSON:      p.cfg.DecodeJSONTG,
		YAML:      p.cfg.DecodeYAMLTG,
	}

	for {
		if ctx.Err() != nil {
			break
		}
		body, err := fetch.GetSecure(ctx, pageURL, 20*time.Second, nil)
		if err != nil {
			return out, err
		}
		messages, nextBefore, err := parsePage(body)
		if err != nil {
			return out, err
		}
		if len(messages) == 0 {
			break
		}
		newMessages := 0
		for _, msg := range messages {
			if _, dup := seenIDs[msg.id]; dup {
				continue
			}
			seenIDs[msg.id] = struct{}{}
			newMessages++
			out.Stats.Messages++
			p.processMessage(msg, options, &out)
			if p.limit > 0 && out.Stats.Messages >= p.limit {
				break
			}
		}
		if p.limit > 0 && out.Stats.Messages >= p.limit {
			break
		}
		if newMessages == 0 || nextBefore <= 0 || (minID != 0 && nextBefore >= minID) {
			break
		}
		minID = nextBefore
		pageURL = fmt.Sprintf("%s?before=%d", base, nextBefore)
		progress := fmt.Sprintf("Прочитано: %d/%d | VLESS:%d Trojan:%d HY2:%d | Base64:%d JSON:%d YAML:%d | Happ:%d | Источников:%d",
			out.Stats.Messages, p.limit, len(out.VLESS), len(out.Trojan), len(out.Hy2),
			out.Stats.Base64, out.Stats.JSON, out.Stats.YAML, out.Stats.Happ, len(out.Sources))
		logx.Progress(out.Stats.Messages, p.limit, "", progress)
		select {
		case <-time.After(250 * time.Millisecond):
		case <-ctx.Done():
			return out, nil
		}
	}
	logx.ClearLine()
	return out, nil
}

func (p *Parser) processMessage(msg message, opt extract.Options, out *channelResult) {
	text := extract.CleanText(msg.text)
	if text != "" {
		res := extract.ExtractFromText(text, opt)
		out.Stats.Base64 += res.Base64
		out.Stats.JSON += res.JSON
		out.Stats.YAML += res.YAML
		for _, v := range res.VLESS {
			out.VLESS[v] = struct{}{}
		}
		for _, t := range res.Trojan {
			out.Trojan[t] = struct{}{}
		}
		for _, h := range res.Hysteria2 {
			out.Hy2[h] = struct{}{}
		}
	}
	if p.cfg.SaveSourcesTG {
		for _, rawURL := range append(extract.FindURLs(text), msg.hrefs...) {
			if strings.Contains(rawURL, "t.me/") || strings.Contains(rawURL, "telegram.me/") {
				continue
			}
			out.Sources[rawURL] = struct{}{}
		}
	}
	if p.cfg.DecryptHappTG {
		for _, link := range extract.FindHapp(text) {
			decrypted, err := safeDecryptHapp(link)
			if err != nil {
				continue
			}
			out.Stats.Happ++
			if p.cfg.SaveSourcesTG {
				out.Sources[decrypted] = struct{}{}
			}
		}
	}
}

type message struct {
	id    int64
	text  string
	hrefs []string
}

// parsePage extracts messages from a t.me/s HTML page. It returns the smallest
// message id so the caller can request older pages with ?before=.
func parsePage(page string) ([]message, int64, error) {
	doc, err := html.Parse(strings.NewReader(page))
	if err != nil {
		return nil, 0, err
	}
	var messages []message
	var minID int64
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "div" && hasClass(n, "tgme_widget_message") {
			if post := attr(n, "data-post"); post != "" {
				if id := postID(post); id > 0 {
					msg := message{id: id}
					if textNode := findMessageText(n); textNode != nil {
						msg.text = nodeText(textNode)
						msg.hrefs = nodeLinks(textNode)
					}
					if msg.text != "" || len(msg.hrefs) > 0 {
						messages = append(messages, msg)
					}
					if minID == 0 || id < minID {
						minID = id
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return messages, minID, nil
}

func hasClass(n *html.Node, class string) bool {
	for _, attr := range n.Attr {
		if attr.Key != "class" {
			continue
		}
		for _, field := range strings.Fields(attr.Val) {
			if field == class {
				return true
			}
		}
	}
	return false
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func postID(post string) int64 {
	i := strings.LastIndexByte(post, '/')
	if i < 0 || i+1 >= len(post) {
		return 0
	}
	id, _ := strconv.ParseInt(post[i+1:], 10, 64)
	return id
}

func findMessageText(n *html.Node) *html.Node {
	var preferred, generic *html.Node
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode {
			// Reply previews contain their own tgme_widget_message_text block;
			// never use the quoted post as the message body.
			if hasClass(node, "tgme_widget_message_reply") {
				return
			}
			if node.Data == "div" && hasClass(node, "tgme_widget_message_text") {
				if hasClass(node, "js-message_text") {
					if preferred == nil {
						preferred = node
					}
				} else if generic == nil {
					generic = node
				}
			}
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	if preferred != nil {
		return preferred
	}
	return generic
}

// safeDecryptHapp guards against a malformed link crashing the whole parser.
func safeDecryptHapp(link string) (out string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("happ: panic: %v", r)
		}
	}()
	return happ.DecryptURL(link)
}

func nodeText(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.TextNode {
			b.WriteString(node.Data)
			return
		}
		if node.Type == html.ElementNode && node.Data == "br" {
			b.WriteString("\n")
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return strings.TrimSpace(b.String())
}

func nodeLinks(n *html.Node) []string {
	var links []string
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "a" {
			if href := attr(node, "href"); href != "" {
				links = append(links, href)
			}
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return links
}

// ChannelName normalises @name, t.me/name and https://t.me/s/name links.
func ChannelName(link string) (string, bool) {
	s := strings.TrimSpace(link)
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "t.me/")
	s = strings.TrimPrefix(s, "telegram.me/")
	s = strings.TrimPrefix(s, "www.t.me/")
	s = strings.TrimPrefix(s, "@")
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	s = strings.Trim(s, "/")
	if strings.HasPrefix(s, "s/") {
		s = strings.TrimPrefix(s, "s/")
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	if s == "" || strings.ContainsAny(s, " \t\n") {
		return "", false
	}
	return s, true
}

func mergeSet(dst map[string]struct{}, src map[string]struct{}) {
	for k := range src {
		dst[k] = struct{}{}
	}
}
