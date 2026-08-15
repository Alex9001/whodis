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
