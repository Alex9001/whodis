package whodis

import (
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
)

type treeTextStyle uint8

const (
	treeTextPlain treeTextStyle = iota
	treeTextTitle
	treeTextLabel
)

type treeNode struct {
	label     string
	value     string
	style     treeTextStyle
	badge     bool
	badgeTone dashboardBadgeTone
	children  []treeNode
}

// renderTree presents the same consolidated data as the dashboard as a
// hierarchy. Like renderPretty, writer is used only to discover terminal
// capabilities; the returned string always ends in exactly one newline.
func renderTree(writer io.Writer, result LookupResult, options RenderOptions) string {
	width := dashboardWidth(writer, options.Width)
	color := dashboardColor(writer, options.Color)
	root := treeRoot(result)
	kind := result.Query.Kind
	if kind == "" {
		kind = result.Object.Kind
	}
	view := buildDashboard(result, options.Details)

	lines := make([]string, 0, len(view.panels)*4+1)
	for _, chunk := range wrapDashboardText(root, width) {
		lines = append(lines, dashboardTitle(chunk, color))
	}

	nodes := make([]treeNode, 0, len(view.panels)+len(view.fullWidth)+1)
	for _, panel := range view.panels {
		nodes = append(nodes, treePanelNode(panel, root, kind))
	}
	for _, panel := range view.fullWidth {
		nodes = append(nodes, treePanelNode(panel, root, kind))
	}
	if view.details != nil {
		nodes = append(nodes, treePanelNode(*view.details, root, kind))
	}
	lines = append(lines, renderTreeNodes(nodes, nil, width, color)...)
	return strings.Join(lines, "\n") + "\n"
}

func treeRoot(result LookupResult) string {
	root := firstNonEmpty(
		safeText(result.Query.Original),
		safeText(result.Query.Canonical),
		safeText(result.Object.Name),
		safeText(result.Object.Handle),
		safeText(result.Object.ASN),
	)
	if root == "" {
		return "Lookup"
	}
	return root
}

func treePanelNode(panel dashboardPanel, root string, kind Kind) treeNode {
	node := treeNode{label: safeText(panel.title), style: treeTextTitle}
	if panel.kind == panelDNSRecords {
		return treeDNSRecordsNode(node, panel.records)
	}

	if len(panel.badges) > 0 {
		statuses := treeNode{label: "Status", style: treeTextLabel, children: make([]treeNode, 0, len(panel.badges))}
		for _, badge := range panel.badges {
			statuses.children = append(statuses.children, treeNode{
				label:     safeText(badge.text),
				badge:     true,
				badgeTone: badge.tone,
			})
		}
		node.children = append(node.children, statuses)
	}

	rootKey := treeIdentifierKey(root, kind)
	for _, row := range panel.rows {
		if treeRowDuplicatesRoot(row, rootKey, kind) {
			continue
		}
		node.children = append(node.children, treeNode{
			label: safeText(row.label),
			value: safeText(row.value),
			style: treeTextLabel,
		})
	}

	if panel.kind == panelDNS && len(panel.items) > 0 {
		items := treeNode{label: "Nameservers", style: treeTextLabel}
		for _, item := range uniqueFold(panel.items) {
			items.children = append(items.children, treeNode{label: safeText(item)})
		}
		node.children = append(node.children, items)
	}

	if panel.kind == panelNotices {
		for _, notice := range panel.notices {
			noticeNode := treeNode{
				label: firstNonEmpty(safeText(notice.title), "Registry notice"),
				style: treeTextTitle,
			}
			for _, description := range notice.descriptions {
				noticeNode.children = append(noticeNode.children, treeNode{
					label: "Description",
					value: safeText(description),
					style: treeTextLabel,
				})
			}
			for _, link := range notice.links {
				noticeNode.children = append(noticeNode.children, treeNode{
					label: "Link",
					value: safeText(link),
					style: treeTextLabel,
				})
			}
			node.children = append(node.children, noticeNode)
		}
	}

	return node
}

func treeDNSRecordsNode(node treeNode, records []DNSRecord) treeNode {
	byType := make(map[string][]DNSRecord)
	for _, record := range records {
		byType[record.Type] = append(byType[record.Type], record)
	}
	types := make([]string, 0, len(byType))
	for recordType := range byType {
		types = append(types, recordType)
	}
	sort.Slice(types, func(left, right int) bool {
		return dnsTypeOrder(types[left]) < dnsTypeOrder(types[right])
	})
	for _, recordType := range types {
		group := treeNode{label: recordType, style: treeTextLabel}
		for _, record := range byType[recordType] {
			value := record.Value
			if record.TTL > 0 {
				value += fmt.Sprintf(" (TTL %ds)", record.TTL)
			}
			group.children = append(group.children, treeNode{label: record.Name, value: value, style: treeTextLabel})
		}
		node.children = append(node.children, group)
	}
	return node
}

func treeRowDuplicatesRoot(row dashboardRow, rootKey string, kind Kind) bool {
	if rootKey == "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(row.label)) {
	case "name", "unicode", "query", "asn", "handle":
		return treeIdentifierKey(row.value, kind) == rootKey
	default:
		return false
	}
}

func treeIdentifierKey(value string, kind Kind) string {
	value = strings.TrimSpace(safeText(value))
	if value == "" {
		return ""
	}
	switch kind {
	case KindIP:
		if prefix, err := netip.ParsePrefix(value); err == nil {
			return prefix.Masked().String()
		}
		if address, err := netip.ParseAddr(value); err == nil {
			return address.String()
		}
	case KindASN:
		upper := strings.ToUpper(value)
		upper = strings.TrimPrefix(upper, "AS")
		if upper != "" && strings.Trim(upper, "0123456789") == "" {
			upper = strings.TrimLeft(upper, "0")
			if upper == "" {
				upper = "0"
			}
			return "as" + upper
		}
	}
	return strings.TrimSuffix(strings.ToLower(value), ".")
}

func renderTreeNodes(nodes []treeNode, ancestorHasMore []bool, width int, color bool) []string {
	lines := make([]string, 0, len(nodes))
	for index, node := range nodes {
		last := index == len(nodes)-1
		lines = append(lines, renderTreeNodeText(node, ancestorHasMore, last, width, color)...)
		if len(node.children) == 0 {
			continue
		}
		childAncestors := append(append([]bool(nil), ancestorHasMore...), !last)
		lines = append(lines, renderTreeNodes(node.children, childAncestors, width, color)...)
	}
	return lines
}

func renderTreeNodeText(node treeNode, ancestors []bool, last bool, width int, color bool) []string {
	firstPrefix, continuationPrefix := treePrefixes(ancestors, last, width)
	contentWidth := max(1, width-dashboardDisplayWidth(firstPrefix))
	label := safeText(node.label)
	value := safeText(node.value)

	if value == "" {
		chunks := wrapDashboardText(label, contentWidth)
		lines := make([]string, 0, len(chunks))
		for index, chunk := range chunks {
			prefix := continuationPrefix
			if index == 0 {
				prefix = firstPrefix
			}
			lines = append(lines, treeStylePrefix(prefix, color)+treeStyleText(chunk, node, color))
		}
		return lines
	}

	heading := label + ": "
	headingWidth := dashboardDisplayWidth(heading)
	valueWidth := contentWidth - headingWidth
	stackedWidth := contentWidth
	if stackedWidth > 2 {
		stackedWidth -= 2
	}
	if label != "" && valueWidth > 0 &&
		(valueWidth >= 8 || dashboardDisplayWidth(value) <= valueWidth) &&
		!dashboardValueBenefitsFromStacking(value, valueWidth, stackedWidth) {
		chunks := wrapDashboardText(value, valueWidth)
		lines := make([]string, 0, len(chunks))
		for index, chunk := range chunks {
			if index == 0 {
				lines = append(lines,
					treeStylePrefix(firstPrefix, color)+
						treeStyleLabel(heading, node.style, color)+
						treeStyleValue(chunk, node, color),
				)
				continue
			}
			lines = append(lines,
				treeStylePrefix(continuationPrefix, color)+
					strings.Repeat(" ", headingWidth)+
					treeStyleValue(chunk, node, color),
			)
		}
		return lines
	}

	// At narrow widths, put the label and value on separate lines. The value
	// retains a small hanging indent wherever the terminal has room for it.
	lines := make([]string, 0)
	labelChunks := wrapDashboardText(label, contentWidth)
	for index, chunk := range labelChunks {
		prefix := continuationPrefix
		if index == 0 {
			prefix = firstPrefix
		}
		lines = append(lines, treeStylePrefix(prefix, color)+treeStyleLabel(chunk, node.style, color))
	}
	indent := 0
	if contentWidth > 2 {
		indent = 2
	}
	for _, chunk := range wrapDashboardText(value, max(1, contentWidth-indent)) {
		lines = append(lines,
			treeStylePrefix(continuationPrefix, color)+
				strings.Repeat(" ", indent)+
				treeStyleValue(chunk, node, color),
		)
	}
	return lines
}

func treePrefixes(ancestors []bool, last bool, width int) (string, string) {
	var base strings.Builder
	for _, hasMore := range ancestors {
		if hasMore {
			base.WriteString("│   ")
		} else {
			base.WriteString("    ")
		}
	}
	first := base.String()
	continuation := first
	if last {
		first += "└── "
		continuation += "    "
	} else {
		first += "├── "
		continuation += "│   "
	}
	if dashboardDisplayWidth(first) < width {
		return first, continuation
	}
	if width >= 3 {
		return "↳ ", "  "
	}
	return "", ""
}

func treeStylePrefix(value string, color bool) string {
	if strings.TrimSpace(value) == "" {
		return value
	}
	return dashboardBorder(value, color)
}

func treeStyleText(value string, node treeNode, color bool) string {
	if node.badge {
		return styleDashboardBadge(value, node.badgeTone, color)
	}
	switch node.style {
	case treeTextTitle:
		return dashboardTitle(value, color)
	case treeTextLabel:
		return dashboardLabel(value, color)
	default:
		return value
	}
}

func treeStyleLabel(value string, style treeTextStyle, color bool) string {
	switch style {
	case treeTextTitle:
		return dashboardTitle(value, color)
	case treeTextLabel:
		return dashboardLabel(value, color)
	default:
		return value
	}
}

func treeStyleValue(value string, node treeNode, color bool) string {
	if node.badge {
		return styleDashboardBadge(value, node.badgeTone, color)
	}
	return value
}
