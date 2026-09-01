package whodis

import (
	"testing"

	mdns "github.com/miekg/dns"
)

func TestEmbeddedRootTrustAnchorsMatchPublishedKeys(t *testing.T) {
	keys := []*mdns.DNSKEY{
		{Hdr: mdns.RR_Header{Name: ".", Rrtype: mdns.TypeDNSKEY, Class: mdns.ClassINET}, Flags: 257, Protocol: 3, Algorithm: 8, PublicKey: "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU="},
		{Hdr: mdns.RR_Header{Name: ".", Rrtype: mdns.TypeDNSKEY, Class: mdns.ClassINET}, Flags: 257, Protocol: 3, Algorithm: 8, PublicKey: "AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc="},
	}
	for _, key := range keys {
		if !matchesAnyDS(key, rootTrustAnchors) {
			t.Fatalf("root key tag %d does not match the embedded IANA DS set", key.KeyTag())
		}
	}
}

func TestParentDNSZone(t *testing.T) {
	for input, want := range map[string]string{"www.example.com.": "example.com.", "com.": ".", ".": "."} {
		if got := parentDNSZone(input); got != want {
			t.Fatalf("parentDNSZone(%q) = %q, want %q", input, got, want)
		}
	}
}
