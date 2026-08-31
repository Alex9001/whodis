package whodis

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestHomepageAnalysisFindsGranularWordPressStackAndStaticSignals(t *testing.T) {
	body := `<!doctype html><html lang="en"><head>
<title>Example</title><meta name="description" content="Description"><meta name="viewport" content="width=device-width">
<link rel="canonical" href="https://example.test/"><link rel="stylesheet" href="/wp-content/plugins/advanced-custom-fields-pro/css/acf.min.css">
<link href="/wp-content/plugins/ninja-forms/assets/forms.css"><link href="/wp-content/plugins/my-client-tool/app.css">
<link href="/wp-content/cache/autoptimize/css/site.css"><link href="/wp-content/themes/genesis/style.css">
<script defer src="/wp-content/plugins/woocommerce/assets/js/woocommerce.min.js"></script>
<script src="https://cdn.example.net/library.js"></script><script type="application/ld+json">{}</script>
</head><body class="woocommerce genesis-title-hidden"><h1>Example</h1><div class="gform_wrapper"></div>
<form><label for="email">Email</label><input id="email"><input id="phone"></form>
<img src="/hero.webp" alt="" width="800" height="600" loading="lazy"><img src="http://images.example.net/photo.jpg">
</body></html>`
	headers := http.Header{
		"Content-Type":              {"text/html; charset=utf-8"},
		"Content-Encoding":          {"br"},
		"Strict-Transport-Security": {"max-age=31536000"},
		"Content-Security-Policy":   {"default-src 'self'; frame-ancestors 'none'"},
		"X-Content-Type-Options":    {"nosniff"},
		"Referrer-Policy":           {"strict-origin-when-cross-origin"},
		"Permissions-Policy":        {"camera=()"},
	}
	profile, components, findings := analyzeHomepage(webInvestigationObservation{
		URL: "https://example.test/", Status: 200, HTTPVersion: "HTTP/2.0", ContentType: headers.Get("Content-Type"),
		ContentEncoding: "br", Headers: headers, Body: []byte(body),
	})
	if profile == nil || len(findings) == 0 {
		t.Fatalf("homepage analysis = (%#v, %#v)", profile, findings)
	}
	for _, name := range []string{"WordPress", "Advanced Custom Fields", "Ninja Forms", "my-client-tool", "Autoptimize", "Genesis Framework", "WooCommerce", "Gravity Forms"} {
		if !hasComponent(components, name) {
			t.Errorf("missing %q in %#v", name, components)
		}
	}
	unknown := homepageComponent(components, "my-client-tool")
	if unknown == nil || unknown.Role != "Unmapped WordPress plugin" || unknown.Confidence != ConfidenceHigh || unknown.Parent != "WordPress" {
		t.Fatalf("unknown plugin = %#v", unknown)
	}
	gravity := homepageComponent(components, "Gravity Forms")
	if gravity == nil || gravity.Confidence != ConfidenceMedium || !containsFold(gravity.Basis, "markup") {
		t.Fatalf("Gravity Forms = %#v", gravity)
	}
	if profile.Assets.Scripts != 2 || profile.Assets.DeferredScripts != 1 || profile.Assets.PotentiallyBlockingScripts != 1 || profile.Assets.Stylesheets != 1 {
		t.Fatalf("asset profile = %#v", profile.Assets)
	}
	if profile.Assets.ThirdPartyOriginTotal != 2 || profile.Security.MixedContentReferences != 1 {
		t.Fatalf("origin/security profile = (%#v, %#v)", profile.Assets, profile.Security)
	}
	if !profile.Metadata.Title || !profile.Metadata.MetaDescription || !profile.Metadata.Viewport || profile.Metadata.CanonicalURL != "https://example.test/" || profile.Metadata.H1Count != 1 || profile.Metadata.StructuredData != 1 {
		t.Fatalf("metadata = %#v", profile.Metadata)
	}
	if !profile.Security.HSTS || !profile.Security.CSP || !profile.Security.FrameProtection || !profile.Security.NoSniff {
		t.Fatalf("security = %#v", profile.Security)
	}
	if !profile.Accessibility.Language || profile.Accessibility.ImagesMissingAlt != 1 || profile.Accessibility.FormControls != 2 || profile.Accessibility.FormControlsMissingLabel != 1 {
		t.Fatalf("accessibility = %#v", profile.Accessibility)
	}
}

func TestHomepageTechnologyIgnoresLooseProductText(t *testing.T) {
	_, components, _ := analyzeHomepage(webInvestigationObservation{
		URL: "https://example.test/", Status: 200, ContentType: "text/html",
		Headers: http.Header{"Content-Type": {"text/html"}},
		Body:    []byte(`<html lang="en"><head><title>Elementor alternatives</title></head><body><p>We migrated away from Elementor.</p></body></html>`),
	})
	if hasComponent(components, "Elementor") {
		t.Fatalf("plain product text produced a technology claim: %#v", components)
	}
}

func TestHomepageSinglePassLabelsAndLazyTechnologyTokens(t *testing.T) {
	profile, components, _ := analyzeHomepage(webInvestigationObservation{
		URL: "https://example.test/", Status: 200, ContentType: "text/html", Headers: http.Header{"Content-Type": {"text/html"}},
		Body: []byte(`<html lang="en"><head><title>Example</title></head><body>
<input id="email"><label for="email">Email</label>
<div class="layout WP-BLOCK-GROUP gform_wrapper"></div>
<section data-elementor-type="page"></section></body></html>`),
	})
	if profile == nil || profile.Accessibility.FormControls != 1 || profile.Accessibility.FormControlsMissingLabel != 0 {
		t.Fatalf("single-pass form label analysis = %#v", profile)
	}
	for _, name := range []string{"WordPress", "Gravity Forms", "Elementor"} {
		if !hasComponent(components, name) {
			t.Errorf("lazy markup inspection missed %q in %#v", name, components)
		}
	}
}

func TestHomepageGeneratorAndMarkupSignalsRemainEvidenceBounded(t *testing.T) {
	profile, components, _ := analyzeHomepage(webInvestigationObservation{
		URL: "https://example.test/", Status: 200, ContentType: "text/html", Headers: http.Header{"Content-Type": {"text/html"}},
		Body: []byte(`<html lang="en"><head><title>Example</title><meta name="generator" content="WooCommerce 9.8.1">
<script src="/wp-content/plugins/%3Cscript%3E/app.js"></script></head><body><div class="wp-block-group"></div>
<input aria-label=" "></body></html>`),
	})
	woocommerce := homepageComponent(components, "WooCommerce")
	if woocommerce == nil || woocommerce.Version != "9.8.1" || woocommerce.Confidence != ConfidenceHigh || !containsFold(woocommerce.Basis, "meta") {
		t.Fatalf("WooCommerce generator component = %#v", woocommerce)
	}
	wordpress := homepageComponent(components, "WordPress")
	if wordpress == nil || wordpress.Confidence != ConfidenceHigh || !containsFold(wordpress.Basis, "asset_path") {
		t.Fatalf("WordPress block component = %#v", wordpress)
	}
	if hasComponent(components, "<script>") || hasComponent(components, "%3cscript%3e") {
		t.Fatalf("unsafe plugin slug became a component: %#v", components)
	}
	if profile == nil || profile.Accessibility.FormControlsMissingLabel != 1 {
		t.Fatalf("empty ARIA label was accepted: %#v", profile)
	}
}

func TestNonHTMLHomepageKeepsHeaderFindingsWithoutMarkupClaims(t *testing.T) {
	profile, _, findings := analyzeHomepage(webInvestigationObservation{
		URL: "https://example.test/feed", Status: 200, HTTPVersion: "HTTP/2.0", ContentType: "application/json", ContentEncoding: "br",
		Headers: http.Header{"Content-Type": {"application/json"}, "Content-Encoding": {"br"}, "Strict-Transport-Security": {"max-age=31536000"}},
		Body:    []byte(`{"status":"ok"}`),
	})
	if profile == nil || profile.MarkupAnalyzed {
		t.Fatalf("non-HTML profile = %#v", profile)
	}
	for _, id := range []string{"web.homepage.response", "web.homepage.html", "web.delivery.compression", "web.security.transport", "web.security.headers"} {
		if !hasFinding(findings, id) {
			t.Errorf("missing header-safe finding %q in %#v", id, findings)
		}
	}
	for _, finding := range findings {
		if finding.ID == "web.delivery.assets" || strings.HasPrefix(finding.ID, "web.seo.") || strings.HasPrefix(finding.ID, "web.accessibility.") {
			t.Fatalf("non-HTML response produced markup finding %#v", finding)
		}
	}
}

func TestHomepageTruncationSuppressesAbsenceFindings(t *testing.T) {
	profile, _, findings := analyzeHomepage(webInvestigationObservation{
		URL: "https://example.test/", Status: 200, ContentType: "text/html", Headers: http.Header{"Content-Type": {"text/html"}},
		Body: []byte(`<html><head><title>Partial`), Truncated: true,
	})
	if profile == nil || !profile.Truncated {
		t.Fatalf("profile = %#v", profile)
	}
	for _, finding := range findings {
		if strings.HasPrefix(finding.ID, "web.seo.") || strings.HasPrefix(finding.ID, "web.accessibility.") {
			t.Fatalf("truncated markup produced absence finding %#v", finding)
		}
	}
}

func TestHomepageEvidenceNeverSerializesCookieValues(t *testing.T) {
	headers := http.Header{"Content-Type": {"text/html"}, "Set-Cookie": {"wp_woocommerce_session_deadbeef=super-secret-value; Secure; HttpOnly"}}
	profile, components, findings := analyzeHomepage(webInvestigationObservation{URL: "https://example.test/", Status: 200, ContentType: "text/html", Headers: headers, Body: []byte(`<html lang="en"><head><title>x</title></head></html>`)})
	payload, err := json.Marshal(struct {
		Profile    *HomepageProfile
		Components []StackComponent
		Findings   []Finding
	}{profile, components, findings})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "super-secret-value") || strings.Contains(string(payload), "deadbeef") || !strings.Contains(string(payload), "wp_woocommerce_session_*") {
		t.Fatalf("serialized evidence leaked or omitted cookie identity: %s", payload)
	}
}

func TestHomepageMinificationUsesConservativeThreeStateHeuristic(t *testing.T) {
	minified := []byte("<html><body>" + strings.Repeat("<span>x</span>", 500) + "</body></html>")
	if _, state := homepageMinification(minified, false); state != HomepageMinificationLikely {
		t.Fatalf("minified state = %q", state)
	}
	pretty := []byte("<html><body>" + strings.Repeat("<div>\n                    <span>x</span>\n                    </div>\n                    ", 300) + "</body></html>")
	if formatting, state := homepageMinification(pretty, false); state != HomepageMinificationNotObserved || formatting < 2<<10 {
		t.Fatalf("pretty state = (%d, %q)", formatting, state)
	}
	if _, state := homepageMinification([]byte("<html></html>"), false); state != HomepageMinificationUnknown {
		t.Fatalf("small document state = %q", state)
	}
}

func homepageComponent(components []StackComponent, name string) *StackComponent {
	for index := range components {
		if components[index].Name == name {
			return &components[index]
		}
	}
	return nil
}

func hasFinding(findings []Finding, id string) bool {
	for _, finding := range findings {
		if finding.ID == id {
			return true
		}
	}
	return false
}
