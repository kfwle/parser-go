package telegram

import (
	"strings"
	"testing"
)

func TestChannelName(t *testing.T) {
	cases := map[string]string{
		"@RKP_channel":                  "RKP_channel",
		"https://t.me/RKP_channel":      "RKP_channel",
		"https://t.me/s/RKP_channel":    "RKP_channel",
		"t.me/RKP_channel/123":          "RKP_channel",
		"http://telegram.me/RKP_chan?x": "RKP_chan",
	}
	for input, want := range cases {
		got, ok := ChannelName(input)
		if !ok || got != want {
			t.Fatalf("%q -> %q ok=%v, want %q", input, got, ok, want)
		}
	}
	if _, ok := ChannelName("   "); ok {
		t.Fatal("empty link accepted")
	}
}

func TestParsePage(t *testing.T) {
	page := `<html><body>
<div class="tgme_widget_message_wrap js-widget_message_wrap">
  <div class="tgme_widget_message text_not_supported_wrap js-widget_message" data-post="chan/100">
    <div class="tgme_widget_message_text js-message_text" dir="auto">vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443#a<br/><a href="https://example.com/sub">source</a></div>
  </div>
</div>
<div class="tgme_widget_message_wrap js-widget_message_wrap">
  <div class="tgme_widget_message js-widget_message" data-post="chan/101">
    <div class="tgme_widget_message_text js-message_text">hello world</div>
  </div>
</div>
</body></html>`
	messages, minID, err := parsePage(page)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 2 {
		t.Fatalf("messages=%d", len(messages))
	}
	if minID != 100 {
		t.Fatalf("minID=%d", minID)
	}
	if !strings.Contains(messages[0].text, "vless://") || !strings.Contains(messages[0].text, "source") {
		t.Fatalf("bad text %q", messages[0].text)
	}
	if len(messages[0].hrefs) != 1 || messages[0].hrefs[0] != "https://example.com/sub" {
		t.Fatalf("bad hrefs %v", messages[0].hrefs)
	}
}

func TestReplyPreviewIsNotMessageText(t *testing.T) {
	page := `<div class="tgme_widget_message js-widget_message" data-post="chan/200">
	  <a class="tgme_widget_message_reply" href="https://t.me/chan/199">
	    <div class="tgme_widget_message_text js-message_reply_text">QUOTED OLD TEXT</div>
	  </a>
	  <div class="tgme_widget_message_text js-message_text">vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443#real</div>
	</div>`
	messages, _, err := parsePage(page)
	if err != nil || len(messages) != 1 {
		t.Fatalf("messages=%v err=%v", messages, err)
	}
	if !strings.Contains(messages[0].text, "vless://") || strings.Contains(messages[0].text, "QUOTED") {
		t.Fatalf("wrong message text: %q", messages[0].text)
	}
}
