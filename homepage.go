package whodis

import (
	"bytes"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/publicsuffix"
)

// HomepageMinification is a conservative source-formatting observation. It is
// not a browser performance score and says nothing about fetched assets.
type HomepageMinification string

const (
	HomepageMinificationLikely      HomepageMinification = "likely"
	HomepageMinificationNotObserved HomepageMinification = "not_observed"
	HomepageMinificationUnknown     HomepageMinification = "unknown"
)

// HomepageProfile contains bounded facts extracted from the one homepage
// response already fetched by Investigate. It never contains the response body.
type HomepageProfile struct {
	URL              string                       `json:"url" yaml:"url"`
	Status           int                          `json:"status,omitempty" yaml:"status,omitempty"`
	HTTPVersion      string                       `json:"http_version,omitempty" yaml:"http_version,omitempty"`
	ContentType      string                       `json:"content_type,omitempty" yaml:"content_type,omitempty"`
	ContentEncoding  string                       `json:"content_encoding,omitempty" yaml:"content_encoding,omitempty"`
	ContentLength    int64                        `json:"content_length,omitempty" yaml:"content_length,omitempty"`
	DecodedBytes     int                          `json:"decoded_bytes,omitempty" yaml:"decoded_bytes,omitempty"`
	Truncated        bool                         `json:"truncated,omitempty" yaml:"truncated,omitempty"`
	CacheControl     string                       `json:"cache_control,omitempty" yaml:"cache_control,omitempty"`
	ETag             bool                         `json:"etag,omitempty" yaml:"etag,omitempty"`
	LastModified     bool                         `json:"last_modified,omitempty" yaml:"last_modified,omitempty"`
	MarkupAnalyzed   bool                         `json:"markup_analyzed" yaml:"markup_analyzed"`
	HTMLMinification HomepageMinification         `json:"html_minification" yaml:"html_minification"`
	FormattingBytes  int                          `json:"formatting_bytes,omitempty" yaml:"formatting_bytes,omitempty"`
	Assets           HomepageAssetProfile         `json:"assets" yaml:"assets"`
	Metadata         HomepageMetadataProfile      `json:"metadata" yaml:"metadata"`
	Security         HomepageSecurityProfile      `json:"security" yaml:"security"`
	Accessibility    HomepageAccessibilityProfile `json:"accessibility" yaml:"accessibility"`
}

type HomepageAssetProfile struct {
	Scripts                    int      `json:"scripts" yaml:"scripts"`
	InlineScripts              int      `json:"inline_scripts" yaml:"inline_scripts"`
	AsyncScripts               int      `json:"async_scripts" yaml:"async_scripts"`
	DeferredScripts            int      `json:"deferred_scripts" yaml:"deferred_scripts"`
	ModuleScripts              int      `json:"module_scripts" yaml:"module_scripts"`
	PotentiallyBlockingScripts int      `json:"potentially_blocking_scripts" yaml:"potentially_blocking_scripts"`
	ScriptsWithMinifiedName    int      `json:"scripts_with_minified_name" yaml:"scripts_with_minified_name"`
	Stylesheets                int      `json:"stylesheets" yaml:"stylesheets"`
	StylesWithMinifiedName     int      `json:"styles_with_minified_name" yaml:"styles_with_minified_name"`
	Images                     int      `json:"images" yaml:"images"`
	LazyImages                 int      `json:"lazy_images" yaml:"lazy_images"`
	ImagesWithDimensions       int      `json:"images_with_dimensions" yaml:"images_with_dimensions"`
	Preloads                   int      `json:"preloads" yaml:"preloads"`
	Preconnects                int      `json:"preconnects" yaml:"preconnects"`
	ThirdPartyOriginTotal      int      `json:"third_party_origin_total" yaml:"third_party_origin_total"`
	ThirdPartyOrigins          []string `json:"third_party_origins,omitempty" yaml:"third_party_origins,omitempty"`
}

type HomepageMetadataProfile struct {
	Title           bool     `json:"title" yaml:"title"`
	MetaDescription bool     `json:"meta_description" yaml:"meta_description"`
	CanonicalURL    string   `json:"canonical_url,omitempty" yaml:"canonical_url,omitempty"`
	Viewport        bool     `json:"viewport" yaml:"viewport"`
	Robots          []string `json:"robots,omitempty" yaml:"robots,omitempty"`
	H1Count         int      `json:"h1_count" yaml:"h1_count"`
	StructuredData  int      `json:"structured_data" yaml:"structured_data"`
	OpenGraph       bool     `json:"open_graph" yaml:"open_graph"`
	TwitterCards    bool     `json:"twitter_cards" yaml:"twitter_cards"`
}

type HomepageSecurityProfile struct {
	HTTPS                  bool `json:"https" yaml:"https"`
	HSTS                   bool `json:"hsts" yaml:"hsts"`
	CSP                    bool `json:"csp" yaml:"csp"`
	FrameProtection        bool `json:"frame_protection" yaml:"frame_protection"`
	NoSniff                bool `json:"no_sniff" yaml:"no_sniff"`
	ReferrerPolicy         bool `json:"referrer_policy" yaml:"referrer_policy"`
	PermissionsPolicy      bool `json:"permissions_policy" yaml:"permissions_policy"`
	MixedContentReferences int  `json:"mixed_content_references" yaml:"mixed_content_references"`
}

type HomepageAccessibilityProfile struct {
	Language                 bool `json:"language" yaml:"language"`
	ImagesMissingAlt         int  `json:"images_missing_alt" yaml:"images_missing_alt"`
	FormControls             int  `json:"form_controls" yaml:"form_controls"`
	FormControlsMissingLabel int  `json:"form_controls_missing_label" yaml:"form_controls_missing_label"`
}

type wordpressProduct struct {
	name   string
	role   string
	traits []string
}

var wordpressPluginProducts = map[string]wordpressProduct{
	"advanced-custom-fields":      {"Advanced Custom Fields", "Content modeling", []string{"WordPress plugins"}},
	"advanced-custom-fields-pro":  {"Advanced Custom Fields", "Content modeling", []string{"WordPress plugins"}},
	"autoptimize":                 {"Autoptimize", "Performance optimization", []string{"WordPress plugins", "Performance"}},
	"beaver-builder-lite-version": {"Beaver Builder", "Page builder", []string{"WordPress plugins", "Page builders"}},
	"contact-form-7":              {"Contact Form 7", "Form builder", []string{"WordPress plugins", "Form builders"}},
	"elementor":                   {"Elementor", "Page builder", []string{"WordPress plugins", "Page builders"}},
	"elementor-pro":               {"Elementor Pro", "Page builder", []string{"WordPress plugins", "Page builders"}},
	"gravityforms":                {"Gravity Forms", "Form builder", []string{"WordPress plugins", "Form builders"}},
	"jetpack":                     {"Jetpack", "WordPress plugin", []string{"WordPress plugins"}},
	"litespeed-cache":             {"LiteSpeed Cache", "Performance optimization", []string{"WordPress plugins", "Caching", "Performance"}},
	"ninja-forms":                 {"Ninja Forms", "Form builder", []string{"WordPress plugins", "Form builders"}},
	"seo-by-rank-math":            {"Rank Math", "SEO", []string{"WordPress plugins", "SEO"}},
	"sitepress-multilingual-cms":  {"WPML", "Localization", []string{"WordPress plugins"}},
	"woocommerce":                 {"WooCommerce", "Ecommerce", []string{"WordPress plugins", "Ecommerce"}},
	"wordpress-seo":               {"Yoast SEO", "SEO", []string{"WordPress plugins", "SEO"}},
	"wp-rocket":                   {"WP Rocket", "Performance optimization", []string{"WordPress plugins", "Caching", "Performance"}},
	"wp-super-cache":              {"WP Super Cache", "Performance optimization", []string{"WordPress plugins", "Caching", "Performance"}},
	"wpforms-lite":                {"WPForms", "Form builder", []string{"WordPress plugins", "Form builders"}},
	"wpforms":                     {"WPForms", "Form builder", []string{"WordPress plugins", "Form builders"}},
	"w3-total-cache":              {"W3 Total Cache", "Performance optimization", []string{"WordPress plugins", "Caching", "Performance"}},
}

var wordpressThemeProducts = map[string]wordpressProduct{
	"genesis": {"Genesis Framework", "WordPress theme framework", []string{"WordPress themes"}},
}

type homepageAnalysis struct {
	profile        HomepageProfile
	components     []StackComponent
	findings       []Finding
	baseURL        *url.URL
	firstParty     string
	thirdParties   map[string]bool
	labels         map[string]bool
	controls       []*html.Node
	technologySeen map[string]bool
}

func analyzeHomepage(web webInvestigationObservation) (*HomepageProfile, []StackComponent, []Finding) {
	if web.URL == "" {
		return nil, nil, nil
	}
	base, _ := url.Parse(web.URL)
	analysis := &homepageAnalysis{
		profile: HomepageProfile{
			URL: web.URL, Status: web.Status, HTTPVersion: web.HTTPVersion, ContentType: web.ContentType,
			ContentEncoding: web.ContentEncoding, ContentLength: web.ContentLength, DecodedBytes: len(web.Body), Truncated: web.Truncated,
			CacheControl: cleanHeaderValue(web.Headers.Get("Cache-Control")), ETag: web.Headers.Get("ETag") != "",
			LastModified: web.Headers.Get("Last-Modified") != "", HTMLMinification: HomepageMinificationUnknown,
		},
		baseURL: base, thirdParties: make(map[string]bool), labels: make(map[string]bool), technologySeen: make(map[string]bool),
	}
	if base != nil {
		analysis.firstParty = siteIdentity(base.Hostname())
		analysis.profile.Security.HTTPS = strings.EqualFold(base.Scheme, "https")
	}
	analysis.inspectSecurity(web.Headers)
	analysis.inspectTechnologyHeaders(web)

	if !homepageLooksLikeHTML(web.ContentType, web.Body) {
		analysis.findings = homepageFindings(analysis.profile)
		analysis.findings = append(analysis.findings, Finding{ID: "web.homepage.html", Severity: SeverityInfo, Title: "Homepage markup", Summary: "The fetched homepage was not identified as HTML, so markup-based observations were unavailable; response-header observations remain available."})
		return &analysis.profile, analysis.components, analysis.findings
	}
	document, err := html.Parse(bytes.NewReader(web.Body))
	if err != nil {
		analysis.findings = homepageFindings(analysis.profile)
		analysis.findings = append(analysis.findings, Finding{ID: "web.homepage.html", Severity: SeverityInfo, Title: "Homepage markup", Summary: "The homepage HTML could not be parsed; header-based observations remain available."})
		return &analysis.profile, analysis.components, analysis.findings
	}
	analysis.profile.MarkupAnalyzed = true
	analysis.collectLabels(document)
	analysis.walk(document)
	analysis.finishAccessibility()
	analysis.profile.Assets.ThirdPartyOriginTotal = len(analysis.thirdParties)
	for origin := range analysis.thirdParties {
		analysis.profile.Assets.ThirdPartyOrigins = append(analysis.profile.Assets.ThirdPartyOrigins, origin)
	}
	sort.Strings(analysis.profile.Assets.ThirdPartyOrigins)
	if len(analysis.profile.Assets.ThirdPartyOrigins) > 20 {
		analysis.profile.Assets.ThirdPartyOrigins = analysis.profile.Assets.ThirdPartyOrigins[:20]
	}
	analysis.profile.FormattingBytes, analysis.profile.HTMLMinification = homepageMinification(web.Body, web.Truncated)
	analysis.findings = homepageFindings(analysis.profile)
	return &analysis.profile, analysis.components, analysis.findings
}

func (analysis *homepageAnalysis) collectLabels(node *html.Node) {
	if node.Type == html.ElementNode && node.Data == "label" {
		if target, ok := htmlAttribute(node, "for"); ok && strings.TrimSpace(target) != "" {
			analysis.labels[target] = true
		}
	}
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		analysis.collectLabels(child)
	}
}

func (analysis *homepageAnalysis) walk(node *html.Node) {
	if node.Type == html.ElementNode {
		analysis.inspectElement(node)
	}
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		analysis.walk(child)
	}
}

func (analysis *homepageAnalysis) inspectElement(node *html.Node) {
	classes, _ := htmlAttribute(node, "class")
	classTokens := strings.Fields(strings.ToLower(classes))
	switch node.Data {
	case "html":
		language, _ := htmlAttribute(node, "lang")
		analysis.profile.Accessibility.Language = strings.TrimSpace(language) != ""
	case "title":
		analysis.profile.Metadata.Title = strings.TrimSpace(htmlNodeText(node)) != ""
	case "meta":
		analysis.inspectMeta(node)
	case "link":
		analysis.inspectLink(node)
	case "script":
		analysis.inspectScript(node)
	case "img":
		analysis.inspectImage(node)
		analysis.inspectResourceAttribute(node, "src")
		if srcset, ok := htmlAttribute(node, "srcset"); ok {
			for _, entry := range strings.Split(srcset, ",") {
				fields := strings.Fields(strings.TrimSpace(entry))
				if len(fields) > 0 {
					analysis.inspectResource(fields[0])
				}
			}
		}
	case "source", "iframe", "video", "audio", "embed":
		analysis.inspectResourceAttribute(node, "src")
	case "h1":
		analysis.profile.Metadata.H1Count++
	case "input", "select", "textarea":
		if isLabelableControl(node) {
			analysis.controls = append(analysis.controls, node)
		}
	}
	analysis.inspectMarkupTechnology(node, classTokens)
}

func (analysis *homepageAnalysis) inspectMeta(node *html.Node) {
	name, _ := htmlAttribute(node, "name")
	property, _ := htmlAttribute(node, "property")
	content, _ := htmlAttribute(node, "content")
	name = strings.ToLower(strings.TrimSpace(name))
	property = strings.ToLower(strings.TrimSpace(property))
	switch name {
	case "description":
		analysis.profile.Metadata.MetaDescription = strings.TrimSpace(content) != ""
	case "viewport":
		analysis.profile.Metadata.Viewport = strings.TrimSpace(content) != ""
	case "robots", "googlebot", "bingbot":
		for _, directive := range strings.Split(strings.ToLower(content), ",") {
			if directive = strings.TrimSpace(directive); directive != "" {
				analysis.profile.Metadata.Robots = append(analysis.profile.Metadata.Robots, directive)
			}
		}
	case "generator":
		analysis.addGeneratorTechnology(content)
	}
	if strings.HasPrefix(name, "twitter:") {
		analysis.profile.Metadata.TwitterCards = true
	}
	if strings.HasPrefix(property, "og:") {
		analysis.profile.Metadata.OpenGraph = true
	}
}

func (analysis *homepageAnalysis) inspectLink(node *html.Node) {
	rel, _ := htmlAttribute(node, "rel")
	href, _ := htmlAttribute(node, "href")
	rels := strings.Fields(strings.ToLower(rel))
	analysis.inspectWordPressPath(resourcePath(href))
	if containsFold(rels, "canonical") {
		if resolved := analysis.resolveResource(href); resolved != nil {
			resolved.RawQuery, resolved.Fragment = "", ""
			analysis.profile.Metadata.CanonicalURL = resolved.String()
		}
	}
	if containsFold(rels, "stylesheet") {
		analysis.profile.Assets.Stylesheets++
		if strings.Contains(strings.ToLower(resourcePath(href)), ".min.css") {
			analysis.profile.Assets.StylesWithMinifiedName++
		}
		analysis.inspectResource(href)
	}
	if containsFold(rels, "preload") {
		analysis.profile.Assets.Preloads++
		analysis.inspectResource(href)
	}
	if containsFold(rels, "preconnect") {
		analysis.profile.Assets.Preconnects++
		analysis.inspectResource(href)
	}
	if strings.Contains(strings.ToLower(rel), "https://api.w.org/") || strings.Contains(strings.ToLower(href), "api.w.org") {
		analysis.addTechnology(StackComponent{Category: StackWebApplication, Name: "WordPress", Role: "CMS", Basis: []string{"meta"}, Confidence: ConfidenceHigh,
			Evidence: []InvestigationEvidence{{Source: "http", Subject: analysis.profile.URL, Field: "link relation", Value: "WordPress REST API"}}})
	}
}

func (analysis *homepageAnalysis) inspectScript(node *html.Node) {
	typeValue, _ := htmlAttribute(node, "type")
	if strings.EqualFold(strings.TrimSpace(typeValue), "application/ld+json") {
		analysis.profile.Metadata.StructuredData++
	}
	source, hasSource := htmlAttribute(node, "src")
	if !hasSource || strings.TrimSpace(source) == "" {
		analysis.profile.Assets.InlineScripts++
		return
	}
	analysis.profile.Assets.Scripts++
	_, async := htmlAttribute(node, "async")
	_, deferValue := htmlAttribute(node, "defer")
	module := strings.EqualFold(strings.TrimSpace(typeValue), "module")
	if async {
		analysis.profile.Assets.AsyncScripts++
	}
	if deferValue {
		analysis.profile.Assets.DeferredScripts++
	}
	if module {
		analysis.profile.Assets.ModuleScripts++
	}
	if hasAncestor(node, "head") && !async && !deferValue && !module {
		analysis.profile.Assets.PotentiallyBlockingScripts++
	}
	if strings.Contains(strings.ToLower(resourcePath(source)), ".min.js") {
		analysis.profile.Assets.ScriptsWithMinifiedName++
	}
	analysis.inspectResource(source)
}

func (analysis *homepageAnalysis) inspectImage(node *html.Node) {
	analysis.profile.Assets.Images++
	if loading, _ := htmlAttribute(node, "loading"); strings.EqualFold(strings.TrimSpace(loading), "lazy") {
		analysis.profile.Assets.LazyImages++
	}
	_, alt := htmlAttribute(node, "alt")
	if !alt {
		analysis.profile.Accessibility.ImagesMissingAlt++
	}
	_, width := htmlAttribute(node, "width")
	_, height := htmlAttribute(node, "height")
	if width && height {
		analysis.profile.Assets.ImagesWithDimensions++
	}
}

func (analysis *homepageAnalysis) inspectResourceAttribute(node *html.Node, name string) {
	if value, ok := htmlAttribute(node, name); ok {
		analysis.inspectResource(value)
	}
}

func (analysis *homepageAnalysis) inspectResource(raw string) {
	resolved := analysis.resolveResource(raw)
	if resolved == nil || resolved.Hostname() == "" {
		return
	}
	if analysis.profile.Security.HTTPS && strings.EqualFold(resolved.Scheme, "http") {
		analysis.profile.Security.MixedContentReferences++
	}
	origin := strings.ToLower(resolved.Scheme + "://" + resolved.Host)
	if siteIdentity(resolved.Hostname()) != analysis.firstParty {
		analysis.thirdParties[origin] = true
	}
	analysis.inspectWordPressPath(resolved.EscapedPath())
}

func (analysis *homepageAnalysis) resolveResource(raw string) *url.URL {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(strings.ToLower(raw), "data:") || strings.HasPrefix(strings.ToLower(raw), "javascript:") {
		return nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	if analysis.baseURL != nil {
		parsed = analysis.baseURL.ResolveReference(parsed)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil
	}
	return parsed
}

func (analysis *homepageAnalysis) inspectWordPressPath(path string) {
	path = strings.ToLower(path)
	if strings.Contains(path, "/wp-content/") || strings.Contains(path, "/wp-includes/") {
		analysis.addTechnology(StackComponent{Category: StackWebApplication, Name: "WordPress", Role: "CMS", Basis: []string{"asset_path"}, Confidence: ConfidenceHigh,
			Evidence: []InvestigationEvidence{{Source: "http", Subject: analysis.profile.URL, Field: "asset path", Value: sanitizeResourcePath(path)}}})
	}
	if slug := wordpressSlug(pathSegmentAfter(path, "/wp-content/plugins/")); slug != "" {
		product, known := wordpressPluginProducts[slug]
		if !known {
			product = wordpressProduct{name: slug, role: "Unmapped WordPress plugin", traits: []string{"WordPress plugins"}}
		}
		analysis.addTechnology(StackComponent{Category: StackWebApplication, Name: product.name, Role: product.role, Parent: "WordPress", Traits: product.traits,
			Basis: []string{"asset_path"}, Confidence: ConfidenceHigh, Summary: "The homepage referenced a public WordPress plugin asset path; this does not prove site-wide activation.",
			Evidence: []InvestigationEvidence{{Source: "http", Subject: analysis.profile.URL, Field: "plugin asset path", Value: sanitizeResourcePath(path)}}})
	}
	if slug := wordpressSlug(pathSegmentAfter(path, "/wp-content/themes/")); slug != "" {
		product, known := wordpressThemeProducts[slug]
		if !known {
			product = wordpressProduct{name: slug, role: "Unmapped WordPress theme", traits: []string{"WordPress themes"}}
		}
		analysis.addTechnology(StackComponent{Category: StackWebApplication, Name: product.name, Role: product.role, Parent: "WordPress", Traits: product.traits,
			Basis: []string{"asset_path"}, Confidence: ConfidenceHigh, Summary: "The homepage referenced a public WordPress theme asset path; this does not prove it is the only active theme.",
			Evidence: []InvestigationEvidence{{Source: "http", Subject: analysis.profile.URL, Field: "theme asset path", Value: sanitizeResourcePath(path)}}})
	}
	if strings.Contains(path, "/wp-content/cache/autoptimize/") {
		product := wordpressPluginProducts["autoptimize"]
		analysis.addTechnology(StackComponent{Category: StackWebApplication, Name: product.name, Role: product.role, Parent: "WordPress", Traits: product.traits,
			Basis: []string{"asset_path"}, Confidence: ConfidenceHigh, Evidence: []InvestigationEvidence{{Source: "http", Subject: analysis.profile.URL, Field: "cache asset path", Value: sanitizeResourcePath(path)}}})
	}
}

func (analysis *homepageAnalysis) inspectMarkupTechnology(node *html.Node, classTokens []string) {
	for _, className := range classTokens {
		var product *wordpressProduct
		switch {
		case strings.HasPrefix(className, "wp-block-"):
			analysis.addTechnology(StackComponent{Category: StackWebApplication, Name: "WordPress", Role: "CMS", Basis: []string{"markup"}, Confidence: ConfidenceMedium,
				Evidence: []InvestigationEvidence{{Source: "http", Subject: analysis.profile.URL, Field: "markup class", Value: className}}})
		case strings.HasPrefix(className, "gform_") || strings.HasPrefix(className, "gform-"):
			value := wordpressPluginProducts["gravityforms"]
			product = &value
		case strings.HasPrefix(className, "nf-form-"):
			value := wordpressPluginProducts["ninja-forms"]
			product = &value
		case className == "woocommerce" || strings.HasPrefix(className, "woocommerce-") || strings.HasPrefix(className, "wc-block-"):
			value := wordpressPluginProducts["woocommerce"]
			product = &value
		case strings.HasPrefix(className, "elementor-"):
			value := wordpressPluginProducts["elementor"]
			product = &value
		case strings.HasPrefix(className, "wpforms-"):
			value := wordpressPluginProducts["wpforms"]
			product = &value
		case strings.HasPrefix(className, "wpcf7"):
			value := wordpressPluginProducts["contact-form-7"]
			product = &value
		case strings.HasPrefix(className, "genesis-") || className == "theme-genesis":
			value := wordpressThemeProducts["genesis"]
			product = &value
		}
		if product != nil {
			analysis.addTechnology(StackComponent{Category: StackWebApplication, Name: product.name, Role: product.role, Parent: "WordPress", Traits: product.traits,
				Basis: []string{"markup"}, Confidence: ConfidenceMedium,
				Evidence: []InvestigationEvidence{{Source: "http", Subject: analysis.profile.URL, Field: "markup class", Value: className}}})
		}
	}
	if _, ok := htmlAttribute(node, "data-elementor-type"); ok {
		product := wordpressPluginProducts["elementor"]
		analysis.addTechnology(StackComponent{Category: StackWebApplication, Name: product.name, Role: product.role, Parent: "WordPress", Traits: product.traits,
			Basis: []string{"markup"}, Confidence: ConfidenceMedium, Evidence: []InvestigationEvidence{{Source: "http", Subject: analysis.profile.URL, Field: "markup attribute", Value: "data-elementor-type"}}})
	}
}

func (analysis *homepageAnalysis) inspectTechnologyHeaders(web webInvestigationObservation) {
	if strings.Contains(strings.ToLower(web.Headers.Get("Link")), "api.w.org") {
		analysis.addTechnology(StackComponent{Category: StackWebApplication, Name: "WordPress", Role: "CMS", Basis: []string{"header"}, Confidence: ConfidenceHigh,
			Evidence: []InvestigationEvidence{{Source: "http", Subject: web.URL, Field: "Link", Value: "WordPress REST API relation"}}})
	}
	if value := cleanHeaderValue(web.Headers.Get("X-LiteSpeed-Cache")); value != "" {
		product := wordpressPluginProducts["litespeed-cache"]
		analysis.addTechnology(StackComponent{Category: StackWebApplication, Name: product.name, Role: product.role, Parent: "WordPress", Traits: product.traits,
			Basis: []string{"header"}, Confidence: ConfidenceHigh, Evidence: []InvestigationEvidence{{Source: "http", Subject: web.URL, Field: "X-LiteSpeed-Cache", Value: value}}})
	}
	response := &http.Response{Header: web.Headers}
	for _, cookie := range response.Cookies() {
		name := strings.ToLower(cookie.Name)
		switch {
		case strings.HasPrefix(name, "woocommerce_") || strings.HasPrefix(name, "wp_woocommerce_session_"):
			product := wordpressPluginProducts["woocommerce"]
			analysis.addTechnology(StackComponent{Category: StackWebApplication, Name: product.name, Role: product.role, Parent: "WordPress", Traits: product.traits,
				Basis: []string{"cookie"}, Confidence: ConfidenceHigh, Evidence: []InvestigationEvidence{{Source: "http", Subject: web.URL, Field: "cookie name pattern", Value: cookieNamePattern(name)}}})
		case strings.HasPrefix(name, "wordpress_") || strings.HasPrefix(name, "wp-settings-"):
			analysis.addTechnology(StackComponent{Category: StackWebApplication, Name: "WordPress", Role: "CMS", Basis: []string{"cookie"}, Confidence: ConfidenceHigh,
				Evidence: []InvestigationEvidence{{Source: "http", Subject: web.URL, Field: "cookie name pattern", Value: cookieNamePattern(name)}}})
		}
	}
}

func (analysis *homepageAnalysis) addGeneratorTechnology(value string) {
	lower := strings.ToLower(value)
	if strings.Contains(lower, "wordpress") {
		version := generatorVersion(value, "wordpress")
		analysis.addTechnology(StackComponent{Category: StackWebApplication, Name: "WordPress", Role: "CMS", Version: version, Basis: []string{"meta"}, Confidence: ConfidenceHigh,
			Evidence: []InvestigationEvidence{{Source: "http", Subject: analysis.profile.URL, Field: "meta generator", Value: truncateEvidence(value)}}})
	}
	for needle, slug := range map[string]string{
		"woocommerce":   "woocommerce",
		"elementor":     "elementor",
		"gravity forms": "gravityforms",
	} {
		if !strings.Contains(lower, needle) {
			continue
		}
		product := wordpressPluginProducts[slug]
		analysis.addTechnology(StackComponent{Category: StackWebApplication, Name: product.name, Role: product.role, Version: generatorVersion(value, needle), Parent: "WordPress",
			Traits: product.traits, Basis: []string{"meta"}, Confidence: ConfidenceHigh,
			Evidence: []InvestigationEvidence{{Source: "http", Subject: analysis.profile.URL, Field: "meta generator", Value: truncateEvidence(value)}}})
	}
}

func (analysis *homepageAnalysis) addTechnology(component StackComponent) {
	key := string(component.Category) + "\x00" + strings.ToLower(canonicalTechnologyName(component.Name)) + "\x00" + strings.Join(component.Basis, ",") + "\x00"
	if len(component.Evidence) > 0 {
		key += component.Evidence[0].Field + "\x00" + component.Evidence[0].Value
	}
	if analysis.technologySeen[key] {
		return
	}
	analysis.technologySeen[key] = true
	analysis.components = append(analysis.components, component)
}

func (analysis *homepageAnalysis) inspectSecurity(headers http.Header) {
	security := &analysis.profile.Security
	security.HSTS = strings.TrimSpace(headers.Get("Strict-Transport-Security")) != ""
	csp := strings.TrimSpace(headers.Get("Content-Security-Policy"))
	security.CSP = csp != ""
	security.FrameProtection = strings.TrimSpace(headers.Get("X-Frame-Options")) != "" || strings.Contains(strings.ToLower(csp), "frame-ancestors")
	security.NoSniff = strings.EqualFold(strings.TrimSpace(headers.Get("X-Content-Type-Options")), "nosniff")
	security.ReferrerPolicy = strings.TrimSpace(headers.Get("Referrer-Policy")) != ""
	security.PermissionsPolicy = strings.TrimSpace(headers.Get("Permissions-Policy")) != ""
}

func (analysis *homepageAnalysis) finishAccessibility() {
	analysis.profile.Metadata.Robots = uniqueStrings(analysis.profile.Metadata.Robots)
	for _, control := range analysis.controls {
		analysis.profile.Accessibility.FormControls++
		id, _ := htmlAttribute(control, "id")
		ariaLabelValue, ariaLabel := htmlAttribute(control, "aria-label")
		ariaLabelledByValue, ariaLabelledBy := htmlAttribute(control, "aria-labelledby")
		ariaLabel = ariaLabel && strings.TrimSpace(ariaLabelValue) != ""
		ariaLabelledBy = ariaLabelledBy && strings.TrimSpace(ariaLabelledByValue) != ""
		if !analysis.labels[id] && !ariaLabel && !ariaLabelledBy && !hasAncestor(control, "label") {
			analysis.profile.Accessibility.FormControlsMissingLabel++
		}
	}
}

func homepageFindings(profile HomepageProfile) []Finding {
	findings := []Finding{homepageResponseFinding(profile)}
	compressionSeverity := SeverityPass
	compressionSummary := "The homepage response used " + profile.ContentEncoding + " content encoding."
	if profile.ContentEncoding == "" {
		compressionSeverity = SeverityInfo
		compressionSummary = "No content encoding was observed for the homepage response."
		if profile.DecodedBytes >= 4<<10 {
			compressionSeverity = SeverityWarning
		}
	}
	findings = append(findings, Finding{ID: "web.delivery.compression", Severity: compressionSeverity, Title: "Homepage compression", Summary: compressionSummary,
		Evidence: map[string]string{"decoded_bytes": strconv.Itoa(profile.DecodedBytes), "content_encoding": profile.ContentEncoding}})

	security := profile.Security
	transportSeverity := SeverityPass
	transportSummary := "The final homepage used HTTPS."
	if profile.MarkupAnalyzed {
		transportSummary = "The final homepage used HTTPS and no insecure asset references were observed in its markup."
	}
	if !security.HTTPS || security.MixedContentReferences > 0 {
		transportSeverity = SeverityWarning
		transportSummary = fmt.Sprintf("Final HTTPS: %t; insecure HTTP asset references: %d.", security.HTTPS, security.MixedContentReferences)
	}
	findings = append(findings, Finding{ID: "web.security.transport", Severity: transportSeverity, Title: "Homepage transport", Summary: transportSummary})
	present := 0
	for _, value := range []bool{security.HSTS, security.CSP, security.FrameProtection, security.NoSniff, security.ReferrerPolicy, security.PermissionsPolicy} {
		if value {
			present++
		}
	}
	headerSeverity := SeverityInfo
	if present == 6 {
		headerSeverity = SeverityPass
	}
	findings = append(findings, Finding{ID: "web.security.headers", Severity: headerSeverity, Title: "Browser security headers",
		Summary: fmt.Sprintf("Observed %d of 6 bounded header protections (HSTS, CSP, frame protection, nosniff, referrer policy, permissions policy). Header absence is context, not a vulnerability claim.", present)})

	if !profile.MarkupAnalyzed {
		return findings
	}

	minificationSeverity := SeverityInfo
	minificationSummary := "HTML minification could not be determined conservatively."
	if profile.HTMLMinification == HomepageMinificationLikely {
		minificationSeverity = SeverityPass
		minificationSummary = "The homepage source appears minified from its inter-tag formatting footprint."
	} else if profile.HTMLMinification == HomepageMinificationNotObserved {
		minificationSummary = "HTML minification was not evident from the homepage source formatting."
	}
	findings = append(findings, Finding{ID: "web.delivery.html_minification", Severity: minificationSeverity, Title: "HTML minification", Summary: minificationSummary,
		Evidence: map[string]string{"state": string(profile.HTMLMinification), "formatting_bytes": strconv.Itoa(profile.FormattingBytes)}})

	assets := profile.Assets
	assetSeverity := SeverityInfo
	if assets.PotentiallyBlockingScripts > 3 {
		assetSeverity = SeverityWarning
	}
	findings = append(findings, Finding{ID: "web.delivery.assets", Severity: assetSeverity, Title: "Homepage asset loading",
		Summary:  fmt.Sprintf("Observed %d external scripts (%d async/deferred/module, %d potentially blocking), %d stylesheets, and %d preloads. Minified filenames are only indicators, not content inspection.", assets.Scripts, min(assets.Scripts, assets.AsyncScripts+assets.DeferredScripts+assets.ModuleScripts), assets.PotentiallyBlockingScripts, assets.Stylesheets, assets.Preloads),
		Evidence: map[string]string{"minified_script_names": strconv.Itoa(assets.ScriptsWithMinifiedName), "minified_style_names": strconv.Itoa(assets.StylesWithMinifiedName)}})
	findings = append(findings, Finding{ID: "web.delivery.third_party", Severity: SeverityInfo, Title: "Third-party origins",
		Summary: fmt.Sprintf("The homepage markup referenced %d origin(s) outside the site's registrable domain; Whodis did not contact them.", assets.ThirdPartyOriginTotal), Evidence: map[string]string{"origins": strings.Join(assets.ThirdPartyOrigins, ", ")}})

	if !profile.Truncated {
		metadata := profile.Metadata
		missingMetadata := make([]string, 0, 5)
		if !metadata.Title {
			missingMetadata = append(missingMetadata, "title")
		}
		if !metadata.MetaDescription {
			missingMetadata = append(missingMetadata, "meta description")
		}
		if metadata.CanonicalURL == "" {
			missingMetadata = append(missingMetadata, "canonical link")
		}
		if !metadata.Viewport {
			missingMetadata = append(missingMetadata, "viewport")
		}
		if metadata.H1Count == 0 {
			missingMetadata = append(missingMetadata, "H1")
		}
		metadataSeverity := SeverityPass
		if len(missingMetadata) > 0 {
			metadataSeverity = SeverityInfo
		}
		if !metadata.Title || !metadata.Viewport {
			metadataSeverity = SeverityWarning
		}
		metadataSummary := "Title, meta description, canonical link, viewport metadata, and an H1 were present."
		if len(missingMetadata) > 0 {
			metadataSummary = "Not observed: " + strings.Join(missingMetadata, ", ") + "."
		}
		findings = append(findings, Finding{ID: "web.seo.metadata", Severity: metadataSeverity, Title: "Homepage metadata", Summary: metadataSummary,
			Evidence: map[string]string{"h1_count": strconv.Itoa(metadata.H1Count), "structured_data_blocks": strconv.Itoa(metadata.StructuredData)}})
		indexingSummary := "No noindex directive was observed in homepage meta tags."
		indexingSeverity := SeverityPass
		if containsFold(metadata.Robots, "noindex") {
			indexingSummary = "A noindex directive was present in homepage meta tags; this may be intentional."
			indexingSeverity = SeverityInfo
		}
		findings = append(findings, Finding{ID: "web.seo.indexing", Severity: indexingSeverity, Title: "Homepage indexing", Summary: indexingSummary, Evidence: map[string]string{"robots": strings.Join(metadata.Robots, ", ")}})
	}

	if !profile.Truncated {
		accessibility := profile.Accessibility
		languageSeverity := SeverityPass
		languageSummary := "The document declared a language."
		if !accessibility.Language {
			languageSeverity = SeverityWarning
			languageSummary = "The document did not declare an HTML language."
		}
		findings = append(findings, Finding{ID: "web.accessibility.language", Severity: languageSeverity, Title: "Document language", Summary: languageSummary})
		imageSeverity := SeverityPass
		if accessibility.ImagesMissingAlt > 0 {
			imageSeverity = SeverityWarning
		}
		findings = append(findings, Finding{ID: "web.accessibility.images", Severity: imageSeverity, Title: "Image alternatives",
			Summary: fmt.Sprintf("%d of %d images lacked an alt attribute; empty alt attributes count as intentional markup.", accessibility.ImagesMissingAlt, assets.Images)})
		formSeverity := SeverityPass
		if accessibility.FormControlsMissingLabel > 0 {
			formSeverity = SeverityWarning
		}
		findings = append(findings, Finding{ID: "web.accessibility.forms", Severity: formSeverity, Title: "Form labels",
			Summary: fmt.Sprintf("%d of %d labelable form controls lacked a static label or ARIA name.", accessibility.FormControlsMissingLabel, accessibility.FormControls)})
	}
	return findings
}

func homepageResponseFinding(profile HomepageProfile) Finding {
	severity := SeverityPass
	if profile.Status < 200 || profile.Status >= 400 {
		severity = SeverityWarning
	}
	summary := fmt.Sprintf("GET %s returned %d over %s (%s decoded).", profile.URL, profile.Status, firstString([]string{profile.HTTPVersion}, "HTTP"), formatByteCount(profile.DecodedBytes))
	if profile.Truncated {
		summary += " Analysis was limited to the first 1 MiB."
	}
	return Finding{ID: "web.homepage.response", Severity: severity, Title: "Homepage response", Summary: summary}
}

func homepageSummary(profile *HomepageProfile) string {
	if profile == nil {
		return ""
	}
	encoding := profile.ContentEncoding
	if encoding == "" {
		encoding = "no encoding observed"
	}
	if !profile.MarkupAnalyzed {
		return fmt.Sprintf("%d · %s · %s · markup not analyzed", profile.Status, firstString([]string{profile.HTTPVersion}, "HTTP"), encoding)
	}
	return fmt.Sprintf("%d · %s · %s · HTML %s · %d scripts · %d styles · %d third-party origins", profile.Status, firstString([]string{profile.HTTPVersion}, "HTTP"), encoding, profile.HTMLMinification, profile.Assets.Scripts, profile.Assets.Stylesheets, profile.Assets.ThirdPartyOriginTotal)
}

func homepageMinification(body []byte, truncated bool) (int, HomepageMinification) {
	if truncated || len(body) < 4<<10 {
		return 0, HomepageMinificationUnknown
	}
	formatting := 0
	for index := 0; index < len(body); index++ {
		if body[index] != '>' {
			continue
		}
		end := index + 1
		for end < len(body) && (body[end] == ' ' || body[end] == '\t' || body[end] == '\r' || body[end] == '\n') {
			end++
		}
		if end < len(body) && body[end] == '<' {
			formatting += end - index - 1
		}
	}
	ratio := float64(formatting) / float64(len(body))
	switch {
	case ratio <= 0.03:
		return formatting, HomepageMinificationLikely
	case ratio >= 0.10 && formatting >= 2<<10:
		return formatting, HomepageMinificationNotObserved
	default:
		return formatting, HomepageMinificationUnknown
	}
}

func homepageLooksLikeHTML(contentType string, body []byte) bool {
	if mediaType, _, err := mime.ParseMediaType(contentType); err == nil && (mediaType == "text/html" || mediaType == "application/xhtml+xml") {
		return true
	}
	prefix := strings.ToLower(string(body[:min(len(body), 512)]))
	return strings.Contains(prefix, "<!doctype html") || strings.Contains(prefix, "<html") || strings.Contains(prefix, "<head")
}

func htmlAttribute(node *html.Node, name string) (string, bool) {
	for _, attribute := range node.Attr {
		if strings.EqualFold(attribute.Key, name) {
			return attribute.Val, true
		}
	}
	return "", false
}

func htmlNodeText(node *html.Node) string {
	var builder strings.Builder
	var walk func(*html.Node)
	walk = func(current *html.Node) {
		if current.Type == html.TextNode {
			builder.WriteString(current.Data)
		}
		for child := current.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(node)
	return builder.String()
}

func hasAncestor(node *html.Node, name string) bool {
	for parent := node.Parent; parent != nil; parent = parent.Parent {
		if parent.Type == html.ElementNode && parent.Data == name {
			return true
		}
	}
	return false
}

func isLabelableControl(node *html.Node) bool {
	if node.Data != "input" {
		return true
	}
	typeValue, _ := htmlAttribute(node, "type")
	switch strings.ToLower(strings.TrimSpace(typeValue)) {
	case "hidden", "button", "submit", "reset", "image":
		return false
	default:
		return true
	}
}

func siteIdentity(host string) string {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if domain, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return domain
	}
	return strings.TrimPrefix(host, "www.")
}

func pathSegmentAfter(path, marker string) string {
	index := strings.Index(path, marker)
	if index < 0 {
		return ""
	}
	value := strings.TrimPrefix(path[index+len(marker):], "/")
	if slash := strings.IndexByte(value, '/'); slash >= 0 {
		value = value[:slash]
	}
	return strings.TrimSpace(value)
}

func wordpressSlug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || len(value) > 100 {
		return ""
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || ((character == '-' || character == '_' || character == '.') && index > 0) {
			continue
		}
		return ""
	}
	return value
}

func generatorVersion(value, product string) string {
	lower := strings.ToLower(value)
	index := strings.Index(lower, strings.ToLower(product))
	if index < 0 {
		return ""
	}
	tail := strings.TrimSpace(value[index+len(product):])
	tail = strings.TrimLeft(tail, "vV :=-/")
	if fields := strings.Fields(tail); len(fields) > 0 {
		candidate := strings.Trim(fields[0], ";,()")
		if candidate != "" && candidate[0] >= '0' && candidate[0] <= '9' {
			return truncateEvidence(candidate)
		}
	}
	return ""
}

func cookieNamePattern(value string) string {
	for _, prefix := range []string{"wp_woocommerce_session_", "wordpress_", "wp-settings-"} {
		if strings.HasPrefix(value, prefix) {
			return prefix + "*"
		}
	}
	return value
}

func sanitizeResourcePath(value string) string {
	if parsed, err := url.Parse(value); err == nil {
		value = parsed.EscapedPath()
	}
	return truncateEvidence(value)
}

func resourcePath(value string) string {
	if parsed, err := url.Parse(value); err == nil {
		return parsed.Path
	}
	return value
}

func formatByteCount(value int) string {
	if value >= 1<<20 {
		return fmt.Sprintf("%.1f MiB", float64(value)/(1<<20))
	}
	if value >= 1<<10 {
		return fmt.Sprintf("%.1f KiB", float64(value)/(1<<10))
	}
	return fmt.Sprintf("%d B", value)
}
