package whodis

import "testing"

func TestParseSubjectUsesOperationSpecificGrammar(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		operation  Operation
		canonical  string
		registered string
	}{
		{name: "URL registration", input: "https://www.example.co.uk/path", operation: OperationRegistration, canonical: "www.example.co.uk", registered: "example.co.uk"},
		{name: "service owner", input: "_sip._tcp.Example.COM", operation: OperationDNSQuery, canonical: "_sip._tcp.example.com"},
		{name: "wildcard", input: "*.example.com", operation: OperationDNSQuery, canonical: "*.example.com"},
		{name: "root", input: ".", operation: OperationDNSQuery, canonical: "."},
		{name: "reverse", input: "192.0.2.1", operation: OperationDNSQuery, canonical: "1.2.0.192.in-addr.arpa."},
		{name: "delegated inventory zone", input: "Delegated.Sub.Example.COM", operation: OperationDNSInventory, canonical: "delegated.sub.example.com"},
		{name: "delegated transfer zone", input: "Delegated.Sub.Example.COM", operation: OperationDNSTransfer, canonical: "delegated.sub.example.com"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			subject, err := ParseSubject(test.input, test.operation)
			if err != nil {
				t.Fatal(err)
			}
			if subject.Canonical != test.canonical || subject.RegistrationDomain != test.registered {
				t.Fatalf("subject = %#v", subject)
			}
		})
	}
}

func TestParseSubjectRejectsActiveOperationForIPAddress(t *testing.T) {
	if _, err := ParseSubject("192.0.2.1", OperationInspect); err == nil {
		t.Fatal("inspect accepted an IP address")
	}
}

func TestParseSubjectDistinguishesASPrefixDomainsFromASNs(t *testing.T) {
	tests := []struct {
		input      string
		canonical  string
		kind       SubjectKind
		registered string
	}{
		{input: "askjeeves.com", canonical: "askjeeves.com", kind: SubjectRegistrableDomain, registered: "askjeeves.com"},
		{input: "https://askjeeves.com/search", canonical: "askjeeves.com", kind: SubjectRegistrableDomain, registered: "askjeeves.com"},
		{input: "aspen.com", canonical: "aspen.com", kind: SubjectRegistrableDomain, registered: "aspen.com"},
		{input: "as15169.com", canonical: "as15169.com", kind: SubjectRegistrableDomain, registered: "as15169.com"},
		{input: "ASbogus", canonical: "asbogus", kind: SubjectRegistrableDomain, registered: "asbogus"},
		{input: "AS", canonical: "as", kind: SubjectRegistrableDomain, registered: "as"},
		{input: "as.", canonical: "as", kind: SubjectRegistrableDomain, registered: "as"},
		{input: "AS15169", canonical: "15169", kind: SubjectASN},
		{input: "as007", canonical: "7", kind: SubjectASN},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			subject, err := ParseSubject(test.input, OperationRegistration)
			if err != nil {
				t.Fatal(err)
			}
			if subject.Canonical != test.canonical || subject.Kind != test.kind || subject.RegistrationDomain != test.registered {
				t.Fatalf("ParseSubject(%q) = %#v", test.input, subject)
			}
		})
	}
	for _, input := range []string{"as4294967296", "AS99999999999"} {
		if _, err := ParseSubject(input, OperationRegistration); err == nil {
			t.Errorf("ParseSubject(%q) accepted an invalid ASN literal", input)
		}
	}
}
