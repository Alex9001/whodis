package whodis

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/mattn/go-runewidth"
	"golang.org/x/term"
)

const maximumDashboardWidth = 1000

type dashboardPanelKind uint8

const (
	panelRows dashboardPanelKind = iota
	panelDNS
	panelNotices
)

type dashboardPanelRole uint8

const (
	panelSupport dashboardPanelRole = iota
	panelPrimary
	panelContacts
)

type dashboardBadgeTone uint8

const (
	badgeStatus dashboardBadgeTone = iota
	badgeConstraint
)

type dashboardBadge struct {
	text string
	tone dashboardBadgeTone
}

type dashboardRow struct {
	label string
	value string
}

type dashboardNotice struct {
	title        string
	descriptions []string
	links        []string
}

type dashboardPanel struct {
	title   string
	kind    dashboardPanelKind
	role    dashboardPanelRole
	badges  []dashboardBadge
	rows    []dashboardRow
	items   []string
	notices []dashboardNotice
}

type dashboardView struct {
	panels  []dashboardPanel
	details *dashboardPanel
}

type dashboardContact struct {
	roles         []string
	handles       []string
	names         []string
	organizations []string
	emails        []string
	phones        []string
}

func renderPretty(writer io.Writer, result LookupResult, options RenderOptions) string {
	width := dashboardWidth(writer, options.Width)
	color := dashboardColor(writer, options.Color)
	view := buildDashboard(result, options.Details)
	lines := renderDashboard(view, width, color)
	return strings.Join(lines, "\n") + "\n"
}

func buildDashboard(result LookupResult, details bool) dashboardView {
	object := result.Object
	kind := result.Query.Kind
	if kind == "" {
		kind = object.Kind
	}

	statusBadges := make([]dashboardBadge, 0, len(object.Status))
	for _, status := range uniqueFold(object.Status) {
		statusBadges = append(statusBadges, dashboardBadge{
			text: strings.ToUpper(status),
			tone: statusBadgeTone(status),
		})
	}

	panels := make([]dashboardPanel, 0, 6)
	switch kind {
	case KindIP:
		rows := dashboardRows(
			"Query", firstNonEmpty(result.Query.Canonical, object.Name, object.Handle),
			"Name", object.Name,
			"Unicode", distinctDashboardValue(object.UnicodeName, object.Name),
			"Handle", object.Handle,
			"Registrar", object.Registrar,
			"Registry", object.Registry,
			"Type", object.NetworkType,
			"Range", joinRange(object.StartAddress, object.EndAddress),
			"CIDR", strings.Join(uniqueFold(object.CIDR), ", "),
			"Country", object.Country,
			"ASN", object.ASN,
			"ASN name", distinctDashboardValue(object.ASNName, object.Name),
			"ASN type", object.ASNType,
		)
		if len(rows) > 0 || len(statusBadges) > 0 {
			panels = append(panels, dashboardPanel{title: "Network", kind: panelRows, role: panelPrimary, badges: statusBadges, rows: rows})
		}
	case KindASN:
		name := firstNonEmpty(object.ASNName, object.Name)
		rows := dashboardRows(
			"ASN", firstNonEmpty(object.ASN, result.Query.Canonical),
			"Name", name,
			"Object name", distinctDashboardValue(object.Name, name),
			"Unicode", distinctDashboardValue(object.UnicodeName, name, object.Name),
			"Type", object.ASNType,
			"Handle", object.Handle,
			"Registrar", object.Registrar,
			"Registry", object.Registry,
			"Network", object.NetworkType,
			"Range", joinRange(object.StartAddress, object.EndAddress),
			"CIDR", strings.Join(uniqueFold(object.CIDR), ", "),
			"Country", object.Country,
		)
		if len(rows) > 0 || len(statusBadges) > 0 {
			panels = append(panels, dashboardPanel{title: "ASN", kind: panelRows, role: panelPrimary, badges: statusBadges, rows: rows})
		}
	default:
		unicodeName := object.UnicodeName
		if dashboardKey(unicodeName) == dashboardKey(object.Name) {
			unicodeName = ""
		}
		rows := dashboardRows(
			"Name", firstNonEmpty(object.Name, result.Query.Canonical),
			"Unicode", unicodeName,
			"Handle", object.Handle,
			"Registrar", object.Registrar,
			"Registry", object.Registry,
			"Network", object.NetworkType,
			"Range", joinRange(object.StartAddress, object.EndAddress),
			"CIDR", strings.Join(uniqueFold(object.CIDR), ", "),
			"Country", object.Country,
			"ASN", object.ASN,
			"ASN name", distinctDashboardValue(object.ASNName, object.Name),
			"ASN type", object.ASNType,
		)
		if len(rows) > 0 || len(statusBadges) > 0 {
			panels = append(panels, dashboardPanel{title: "Registration", kind: panelRows, role: panelPrimary, badges: statusBadges, rows: rows})
		}
	}

	events := consolidateEvents(object.Events)
	if len(events) > 0 {
		panels = append(panels, dashboardPanel{
			title: fmt.Sprintf("Timeline · %d", len(events)),
			kind:  panelRows,
			rows:  events,
		})
	}

	nameservers := uniqueFold(object.Nameservers)
	dnsRows := dashboardRows("DNSSEC", object.DNSSEC)
	if len(dnsRows) > 0 || len(nameservers) > 0 {
		title := "DNS"
		if len(nameservers) > 0 {
			title = fmt.Sprintf("DNS · %d", len(nameservers))
		}
		panels = append(panels, dashboardPanel{title: title, kind: panelDNS, rows: dnsRows, items: nameservers})
	}

	contacts := consolidateContacts(object.Entities)
	if len(contacts) > 0 {
		rows := make([]dashboardRow, 0, len(contacts))
		for _, contact := range contacts {
			rows = append(rows, dashboardRow{
				label: strings.Join(contact.roles, " / "),
				value: dashboardContactValue(contact),
			})
		}
		panels = append(panels, dashboardPanel{
			title: fmt.Sprintf("Contacts · %d", len(contacts)),
			kind:  panelRows,
			role:  panelContacts,
			rows:  rows,
		})
	}

	notices := consolidateNotices(object.Notices)
	sourceRows := dashboardRows(
		"Protocol", strings.ToUpper(string(result.Route.Protocol)),
		"Authority", result.Route.Endpoint,
		"Discovery", result.Route.DiscoverySource,
	)
	if !result.RetrievedAt.IsZero() {
		sourceRows = append(sourceRows, dashboardRow{label: "Retrieved", value: result.RetrievedAt.UTC().Format("2006-01-02 15:04:05 UTC")})
	}
	if result.FallbackFrom != nil {
		sourceRows = append(sourceRows, dashboardRow{
			label: "Fallback",
			value: strings.ToUpper(string(result.FallbackFrom.Protocol)) + " → " + strings.ToUpper(string(result.Route.Protocol)),
		})
	}
	if len(notices) > 0 {
		value := fmt.Sprintf("%d hidden · use --details", len(notices))
		if details {
			value = fmt.Sprintf("%d shown below", len(notices))
		}
		sourceRows = append(sourceRows, dashboardRow{label: "Notices", value: value})
	}
	if len(sourceRows) > 0 {
		panels = append(panels, dashboardPanel{title: "Source", kind: panelRows, rows: sourceRows})
	}

	view := dashboardView{panels: panels}
	if details && len(notices) > 0 {
		panel := dashboardPanel{
			title:   fmt.Sprintf("Notices · %d", len(notices)),
			kind:    panelNotices,
			notices: notices,
		}
		view.details = &panel
	}
	return view
}

func renderDashboard(view dashboardView, width int, color bool) []string {
	if width < 1 {
		width = 1
	}
	if width < 32 {
		panels := append([]dashboardPanel(nil), view.panels...)
		if view.details != nil {
			panels = append(panels, *view.details)
		}
		return renderBorderlessDashboard(panels, width, color)
	}

	lines := renderDashboardColumns(view.panels, width, color)
	if view.details != nil {
		if len(lines) > 0 {
			lines = append(lines, "")
		}
		lines = append(lines, renderDashboardPanel(*view.details, width, color)...)
	}
	return lines
}

func renderBorderlessDashboard(panels []dashboardPanel, width int, color bool) []string {
	lines := make([]string, 0)
	for index, panel := range panels {
		if index > 0 {
			lines = append(lines, "")
		}
		for _, titleLine := range wrapDashboardText("["+panel.title+"]", width) {
			lines = append(lines, dashboardTitle(titleLine, color))
		}
		lines = append(lines, renderDashboardBody(panel, width, color)...)
	}
	return lines
}

func renderDashboardColumns(panels []dashboardPanel, width int, color bool) []string {
	columnCount := 1
	if width >= 120 {
		columnCount = 3
	} else if width >= 80 {
		columnCount = 2
	}
	if columnCount > len(panels) {
		columnCount = len(panels)
	}
	if columnCount <= 1 {
		lines := make([]string, 0)
		for index, panel := range panels {
			if index > 0 {
				lines = append(lines, "")
			}
			lines = append(lines, renderDashboardPanel(panel, width, color)...)
		}
		return lines
	}

	widths := dashboardColumnWidths(width, columnCount)
	columns := assignDashboardPanels(panels, widths, color)
	rendered := make([][]string, columnCount)
	maximumHeight := 0
	for columnIndex, column := range columns {
		for panelIndex, panel := range column {
			if panelIndex > 0 {
				rendered[columnIndex] = append(rendered[columnIndex], "")
			}
			rendered[columnIndex] = append(rendered[columnIndex], renderDashboardPanel(panel, widths[columnIndex], color)...)
		}
		if len(rendered[columnIndex]) > maximumHeight {
			maximumHeight = len(rendered[columnIndex])
		}
	}

	lines := make([]string, 0, maximumHeight)
	for lineIndex := 0; lineIndex < maximumHeight; lineIndex++ {
		var builder strings.Builder
		for columnIndex := 0; columnIndex < columnCount; columnIndex++ {
			if columnIndex > 0 {
				builder.WriteByte(' ')
			}
			line := ""
			if lineIndex < len(rendered[columnIndex]) {
				line = rendered[columnIndex][lineIndex]
			}
			builder.WriteString(padDashboardText(line, widths[columnIndex]))
		}
		lines = append(lines, strings.TrimRight(builder.String(), " "))
	}
	return lines
}

func dashboardColumnWidths(width, count int) []int {
	available := width - (count - 1)
	widths := make([]int, count)
	if count == 2 {
		widths[0] = available / 2
		widths[1] = available - widths[0]
		return widths
	}
	// Keep three-column dashboards balanced until the narrow supporting column
	// can hold timestamps and URLs without pathological wrapping. Wider
	// terminals then graduate to the more expressive 5/4/3 mosaic.
	if available < 144 {
		widths[0] = available / 3
		widths[1] = available / 3
		widths[2] = available - widths[0] - widths[1]
		return widths
	}
	weights := []int{5, 4, 3}
	remaining := available
	remainingWeight := 12
	for index := range widths {
		if index == len(widths)-1 {
			widths[index] = remaining
			break
		}
		widths[index] = remaining * weights[index] / remainingWeight
		remaining -= widths[index]
		remainingWeight -= weights[index]
	}
	return widths
}

func assignDashboardPanels(panels []dashboardPanel, widths []int, color bool) [][]dashboardPanel {
	columns := make([][]dashboardPanel, len(widths))
	heights := make([]int, len(widths))
	placed := make([]bool, len(panels))
	place := func(panelIndex, columnIndex int) {
		if len(columns[columnIndex]) > 0 {
			heights[columnIndex]++
		}
		panel := panels[panelIndex]
		columns[columnIndex] = append(columns[columnIndex], panel)
		heights[columnIndex] += len(renderDashboardPanel(panel, widths[columnIndex], color))
		placed[panelIndex] = true
	}

	for panelIndex, panel := range panels {
		if panel.role == panelPrimary {
			place(panelIndex, 0)
			break
		}
	}
	if len(widths) > 1 {
		for panelIndex, panel := range panels {
			if panel.role == panelContacts {
				place(panelIndex, 1)
				break
			}
		}
	}
	for {
		panelIndex := -1
		panelHeight := -1
		for candidateIndex, panel := range panels {
			if placed[candidateIndex] {
				continue
			}
			height := 0
			for _, width := range widths {
				height = max(height, len(renderDashboardPanel(panel, width, color)))
			}
			if height > panelHeight {
				panelIndex = candidateIndex
				panelHeight = height
			}
		}
		if panelIndex < 0 {
			break
		}

		target := -1
		for columnIndex := range columns {
			if len(columns[columnIndex]) == 0 {
				target = columnIndex
				break
			}
		}
		if target < 0 {
			target = 0
			for columnIndex := 1; columnIndex < len(columns); columnIndex++ {
				if heights[columnIndex] < heights[target] {
					target = columnIndex
				}
			}
		}
		place(panelIndex, target)
	}
	return columns
}

func renderDashboardPanel(panel dashboardPanel, width int, color bool) []string {
	if width < 4 {
		return renderBorderlessDashboard([]dashboardPanel{panel}, width, color)
	}
	innerWidth := width - 4
	title := truncateDashboardText(safeText(panel.title), width-6)
	prefix := "╭─ " + title + " "
	dashes := strings.Repeat("─", max(0, width-dashboardDisplayWidth(prefix)-1))
	top := prefix + dashes + "╮"
	if color {
		top = dashboardBorder("╭─ ", true) + dashboardTitle(title, true) + dashboardBorder(" "+dashes+"╮", true)
	}
	lines := []string{top}
	for _, bodyLine := range renderDashboardBody(panel, innerWidth, color) {
		left, right := "│ ", " │"
		if color {
			left, right = dashboardBorder(left, true), dashboardBorder(right, true)
		}
		lines = append(lines, left+padDashboardText(bodyLine, innerWidth)+right)
	}
	bottom := "╰" + strings.Repeat("─", width-2) + "╯"
	if color {
		bottom = dashboardBorder(bottom, true)
	}
	lines = append(lines, bottom)
	return lines
}

func renderDashboardBody(panel dashboardPanel, width int, color bool) []string {
	if width < 1 {
		width = 1
	}
	switch panel.kind {
	case panelDNS:
		lines := renderDashboardRows(panel.rows, width, color)
		if len(panel.items) > 0 {
			if len(lines) > 0 {
				lines = append(lines, "")
			}
			lines = append(lines, renderDashboardItems(panel.items, width, color)...)
		}
		return lines
	case panelNotices:
		return renderDashboardNotices(panel.notices, width, color)
	default:
		lines := renderDashboardBadges(panel.badges, width, color)
		if len(lines) > 0 && len(panel.rows) > 0 {
			lines = append(lines, "")
		}
		return append(lines, renderDashboardRows(panel.rows, width, color)...)
	}
}

func renderDashboardBadges(badges []dashboardBadge, width int, color bool) []string {
	lines := make([]string, 0, 2)
	current := ""
	currentWidth := 0
	flush := func() {
		if current != "" {
			lines = append(lines, current)
			current, currentWidth = "", 0
		}
	}
	for _, badge := range badges {
		plain := "[" + safeText(badge.text) + "]"
		if dashboardDisplayWidth(plain) > width {
			flush()
			for _, chunk := range wrapDashboardText(plain, width) {
				lines = append(lines, styleDashboardBadge(chunk, badge.tone, color))
			}
			continue
		}
		separator := 0
		if current != "" {
			separator = 1
		}
		if currentWidth+separator+dashboardDisplayWidth(plain) > width {
			flush()
		}
		if current != "" {
			current += " "
			currentWidth++
		}
		current += styleDashboardBadge(plain, badge.tone, color)
		currentWidth += dashboardDisplayWidth(plain)
	}
	flush()
	return lines
}

func renderDashboardRows(rows []dashboardRow, width int, color bool) []string {
	if len(rows) == 0 {
		return nil
	}
	maximumLabel := 0
	for _, row := range rows {
		if labelWidth := dashboardDisplayWidth(row.label); labelWidth > maximumLabel {
			maximumLabel = labelWidth
		}
	}
	aligned := width >= 34 && maximumLabel <= 16 && width-maximumLabel-2 >= 14
	if aligned {
		valueWidth := width - maximumLabel - 2
		for _, row := range rows {
			for _, word := range strings.Fields(row.value) {
				if dashboardDisplayWidth(word) > valueWidth {
					aligned = false
					break
				}
			}
			if !aligned {
				break
			}
		}
	}
	lines := make([]string, 0, len(rows))
	for _, row := range rows {
		label := safeText(row.label)
		value := safeText(row.value)
		if value == "" {
			continue
		}
		if !aligned {
			if label != "" {
				for _, chunk := range wrapDashboardText(label, width) {
					lines = append(lines, dashboardLabel(chunk, color))
				}
			}
			indent := 0
			if width > 2 {
				indent = 2
			}
			for _, chunk := range wrapDashboardText(value, max(1, width-indent)) {
				lines = append(lines, strings.Repeat(" ", indent)+chunk)
			}
			continue
		}
		valueWidth := width - maximumLabel - 2
		chunks := wrapDashboardText(value, valueWidth)
		for index, chunk := range chunks {
			rowLabel := ""
			if index == 0 {
				rowLabel = dashboardLabel(label, color)
			}
			lines = append(lines, padDashboardText(rowLabel, maximumLabel)+"  "+chunk)
		}
	}
	return lines
}

func renderDashboardItems(items []string, width int, color bool) []string {
	items = uniqueFold(items)
	if len(items) == 0 {
		return nil
	}
	maximum := 0
	for _, item := range items {
		if itemWidth := dashboardDisplayWidth(item); itemWidth > maximum {
			maximum = itemWidth
		}
	}
	const columnGap = 2
	columnCount := (width + columnGap) / max(1, maximum+2+columnGap)
	if columnCount < 1 {
		columnCount = 1
	}
	if columnCount > 3 {
		columnCount = 3
	}
	if columnCount > len(items) {
		columnCount = len(items)
	}
	if columnCount == 1 {
		lines := make([]string, 0, len(items))
		for _, item := range items {
			marker, continuation := "• ", "  "
			contentWidth := width - 2
			if width < 3 {
				marker, continuation = "", ""
				contentWidth = width
			}
			chunks := wrapDashboardText(item, max(1, contentWidth))
			for index, chunk := range chunks {
				prefix := continuation
				if index == 0 {
					prefix = marker
					if color {
						prefix = paint(prefix, "38;5;45", "", "1")
					}
				}
				lines = append(lines, prefix+chunk)
			}
		}
		return lines
	}

	gap := columnGap
	columnWidth := (width - gap*(columnCount-1)) / columnCount
	lines := make([]string, 0, (len(items)+columnCount-1)/columnCount)
	for start := 0; start < len(items); start += columnCount {
		var builder strings.Builder
		for column := 0; column < columnCount; column++ {
			if column > 0 {
				builder.WriteString(strings.Repeat(" ", gap))
			}
			index := start + column
			value := ""
			if index < len(items) {
				value = "• " + truncateDashboardText(items[index], columnWidth-2)
			}
			builder.WriteString(padDashboardText(value, columnWidth))
		}
		lines = append(lines, strings.TrimRight(builder.String(), " "))
	}
	return lines
}

func renderDashboardNotices(notices []dashboardNotice, width int, color bool) []string {
	lines := make([]string, 0)
	for noticeIndex, notice := range notices {
		if noticeIndex > 0 {
			lines = append(lines, "")
		}
		title := firstNonEmpty(notice.title, "Registry notice")
		for _, chunk := range wrapDashboardText(title, width) {
			lines = append(lines, dashboardTitle(chunk, color))
		}
		indent := 0
		if width > 2 {
			indent = 2
		}
		for _, description := range notice.descriptions {
			for _, chunk := range wrapDashboardText(description, max(1, width-indent)) {
				lines = append(lines, strings.Repeat(" ", indent)+chunk)
			}
		}
		for _, link := range notice.links {
			prefix, continuation := "↗ ", "  "
			contentWidth := width - 2
			if width < 3 {
				prefix, continuation = "", ""
				contentWidth = width
			}
			for index, chunk := range wrapDashboardText(link, max(1, contentWidth)) {
				linePrefix := continuation
				if index == 0 {
					linePrefix = prefix
				}
				value := linePrefix + chunk
				if color {
					value = paint(value, "38;5;45", "", "")
				}
				lines = append(lines, value)
			}
		}
	}
	return lines
}

func consolidateEvents(events []Event) []dashboardRow {
	rows := make([]dashboardRow, 0, len(events))
	indexes := make(map[string]int)
	for _, event := range events {
		action := safeText(event.Action)
		date := safeText(event.Date)
		if action == "" && date == "" {
			continue
		}
		if date == "" {
			date = "unknown"
		}
		key := dashboardKey(action)
		if key == "" {
			key = "event"
			action = "Event"
		}
		if index, ok := indexes[key]; ok {
			if rows[index].value == "unknown" && date != "unknown" {
				rows[index].value = date
				continue
			}
			if date == "unknown" {
				continue
			}
			dates := strings.Split(rows[index].value, " · ")
			rows[index].value = strings.Join(appendUniqueFold(dates, date), " · ")
			continue
		}
		indexes[key] = len(rows)
		rows = append(rows, dashboardRow{label: prettyDashboardLabel(action), value: date})
	}
	return rows
}

func consolidateContacts(entities []Entity) []dashboardContact {
	candidates := make([]dashboardContact, 0, len(entities))
	for _, entity := range entities {
		contact := dashboardContact{
			roles:         uniqueFold(entity.Roles),
			handles:       uniqueFold([]string{entity.Handle}),
			names:         uniqueFold([]string{entity.Name}),
			organizations: uniqueFold([]string{entity.Organization}),
			emails:        uniqueFold([]string{entity.Email}),
			phones:        uniqueFold([]string{entity.Phone}),
		}
		if len(contact.names) > 0 && len(contact.organizations) > 0 &&
			dashboardKey(contact.names[0]) == dashboardKey(contact.organizations[0]) {
			contact.names = nil
		}
		if dashboardContactValue(contact) == "" {
			continue
		}
		candidates = append(candidates, contact)
	}
	if len(candidates) < 2 {
		return candidates
	}

	parents := make([]int, len(candidates))
	for index := range parents {
		parents[index] = index
	}
	var find func(int) int
	find = func(index int) int {
		if parents[index] != index {
			parents[index] = find(parents[index])
		}
		return parents[index]
	}
	union := func(left, right int) {
		left, right = find(left), find(right)
		if left == right {
			return
		}
		if left < right {
			parents[right] = left
		} else {
			parents[left] = right
		}
	}
	for left := 0; left < len(candidates); left++ {
		for right := left + 1; right < len(candidates); right++ {
			if shouldMergeDashboardContacts(candidates[left], candidates[right]) {
				union(left, right)
			}
		}
	}

	groupIndexes := make(map[int]int)
	contacts := make([]dashboardContact, 0, len(candidates))
	for index, candidate := range candidates {
		root := find(index)
		groupIndex, ok := groupIndexes[root]
		if !ok {
			groupIndex = len(contacts)
			groupIndexes[root] = groupIndex
			contacts = append(contacts, dashboardContact{})
		}
		mergeDashboardContact(&contacts[groupIndex], candidate)
	}
	return contacts
}

func shouldMergeDashboardContacts(left, right dashboardContact) bool {
	if dashboardContactSignature(left) == dashboardContactSignature(right) {
		return true
	}
	fieldsLeft := [][]string{left.handles, left.names, left.organizations, left.emails, left.phones}
	fieldsRight := [][]string{right.handles, right.names, right.organizations, right.emails, right.phones}
	sharedSignals := 0
	sharedStrong := false
	for index := range fieldsLeft {
		leftValue, rightValue := firstDashboardValue(fieldsLeft[index]), firstDashboardValue(fieldsRight[index])
		leftKey, rightKey := dashboardKey(leftValue), dashboardKey(rightValue)
		if leftKey != "" && rightKey != "" && leftKey != rightKey {
			return false
		}
		if leftKey == "" || leftKey != rightKey || genericDashboardIdentity(leftKey) {
			continue
		}
		sharedSignals++
		if index == 0 || index == 3 || index == 4 {
			sharedStrong = true
		}
	}
	if sharedDashboardParty(left, right) {
		sharedSignals++
	}
	return sharedStrong && sharedSignals >= 2
}

func sharedDashboardParty(left, right dashboardContact) bool {
	leftValues := append(append([]string{}, left.names...), left.organizations...)
	rightValues := append(append([]string{}, right.names...), right.organizations...)
	for _, leftValue := range leftValues {
		leftKey := dashboardKey(leftValue)
		if leftKey == "" || genericDashboardIdentity(leftKey) {
			continue
		}
		for _, rightValue := range rightValues {
			if leftKey == dashboardKey(rightValue) {
				return true
			}
		}
	}
	return false
}

func dashboardContactSignature(contact dashboardContact) string {
	return strings.Join([]string{
		"handle=" + dashboardKey(firstDashboardValue(contact.handles)),
		"name=" + dashboardKey(firstDashboardValue(contact.names)),
		"organization=" + dashboardKey(firstDashboardValue(contact.organizations)),
		"email=" + dashboardKey(firstDashboardValue(contact.emails)),
		"phone=" + dashboardKey(firstDashboardValue(contact.phones)),
	}, "|")
}

func firstDashboardValue(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func genericDashboardIdentity(value string) bool {
	for _, marker := range []string{
		"redacted", "privacy", "withheld", "not disclosed", "not applicable",
		"data protected", "unavailable", "unknown", "n/a",
	} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

func mergeDashboardContact(target *dashboardContact, addition dashboardContact) {
	target.roles = appendUniqueFold(target.roles, addition.roles...)
	target.handles = appendUniqueFold(target.handles, addition.handles...)
	target.names = appendUniqueFold(target.names, addition.names...)
	target.organizations = appendUniqueFold(target.organizations, addition.organizations...)
	target.emails = appendUniqueFold(target.emails, addition.emails...)
	target.phones = appendUniqueFold(target.phones, addition.phones...)
}

func dashboardContactValue(contact dashboardContact) string {
	parts := make([]string, 0, 8)
	for _, name := range contact.names {
		duplicate := false
		for _, organization := range contact.organizations {
			if dashboardKey(name) == dashboardKey(organization) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			parts = appendUniqueFold(parts, name)
		}
	}
	parts = appendUniqueFold(parts, contact.organizations...)
	for _, handle := range contact.handles {
		if handle != "" {
			parts = appendUniqueFold(parts, "handle "+handle)
		}
	}
	parts = appendUniqueFold(parts, contact.emails...)
	parts = appendUniqueFold(parts, contact.phones...)
	return strings.Join(parts, " · ")
}

func consolidateNotices(notices []Notice) []dashboardNotice {
	grouped := make([]dashboardNotice, 0, len(notices))
	indexes := make(map[string]int)
	for _, notice := range notices {
		title := safeText(notice.Title)
		descriptions := uniqueFold(notice.Description)
		links := uniqueFold(notice.Links)
		if title == "" && len(descriptions) == 0 && len(links) == 0 {
			continue
		}
		key := dashboardKey(title)
		if key == "" {
			key = "untitled:" + dashboardKey(strings.Join(descriptions, "|")) + ":" + dashboardKey(strings.Join(links, "|"))
		}
		if index, ok := indexes[key]; ok {
			grouped[index].descriptions = appendUniqueFold(grouped[index].descriptions, descriptions...)
			grouped[index].links = appendUniqueFold(grouped[index].links, links...)
			continue
		}
		indexes[key] = len(grouped)
		grouped = append(grouped, dashboardNotice{title: title, descriptions: descriptions, links: links})
	}
	return grouped
}

func dashboardRows(values ...string) []dashboardRow {
	rows := make([]dashboardRow, 0, len(values)/2)
	for index := 0; index+1 < len(values); index += 2 {
		label, value := safeText(values[index]), safeText(values[index+1])
		if value != "" {
			rows = append(rows, dashboardRow{label: label, value: value})
		}
	}
	return rows
}

func distinctDashboardValue(value string, existing ...string) string {
	key := dashboardKey(value)
	if key == "" {
		return ""
	}
	for _, other := range existing {
		if key == dashboardKey(other) {
			return ""
		}
	}
	return value
}

func appendUniqueFold(values []string, additions ...string) []string {
	seen := make(map[string]struct{}, len(values)+len(additions))
	for _, value := range values {
		if key := dashboardKey(value); key != "" {
			seen[key] = struct{}{}
		}
	}
	for _, value := range additions {
		value = safeText(value)
		key := dashboardKey(value)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		values = append(values, value)
	}
	return values
}

func uniqueFold(values []string) []string {
	return appendUniqueFold(nil, values...)
}

func dashboardKey(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(safeText(value)), " "))
}

func statusBadgeTone(status string) dashboardBadgeTone {
	normalized := strings.Map(func(character rune) rune {
		if unicode.IsLetter(character) || unicode.IsDigit(character) {
			return unicode.ToLower(character)
		}
		return -1
	}, safeText(status))
	for _, marker := range []string{"prohibited", "hold", "inactive", "pending", "redemption", "locked"} {
		if strings.Contains(normalized, marker) {
			return badgeConstraint
		}
	}
	return badgeStatus
}

func prettyDashboardLabel(value string) string {
	value = strings.NewReplacer("_", " ", "-", " ").Replace(safeText(value))
	if value == "" {
		return ""
	}
	runes := []rune(value)
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}

func dashboardWidth(writer io.Writer, explicit int) int {
	if explicit > 0 {
		return min(explicit, maximumDashboardWidth)
	}
	if file, ok := writer.(interface{ Fd() uintptr }); ok {
		fd := int(file.Fd())
		if term.IsTerminal(fd) {
			if width, _, err := term.GetSize(fd); err == nil && width > 0 {
				return min(width, maximumDashboardWidth)
			}
		}
	}
	if columns, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && columns > 0 {
		return min(columns, maximumDashboardWidth)
	}
	return 80
}

func dashboardColor(writer io.Writer, choice string) bool {
	switch strings.ToLower(strings.TrimSpace(choice)) {
	case "always":
		return true
	case "never":
		return false
	}
	if os.Getenv("NO_COLOR") != "" || strings.EqualFold(os.Getenv("TERM"), "dumb") {
		return false
	}
	file, ok := writer.(interface{ Fd() uintptr })
	return ok && term.IsTerminal(int(file.Fd()))
}

func wrapDashboardText(value string, width int) []string {
	if width < 1 {
		width = 1
	}
	value = safeText(value)
	if value == "" {
		return []string{""}
	}
	words := strings.Fields(value)
	if len(words) == 0 {
		return []string{""}
	}
	lines := make([]string, 0, len(words))
	line := ""
	for _, originalWord := range words {
		word := originalWord
		for dashboardDisplayWidth(word) > width {
			if line != "" {
				lines = append(lines, line)
				line = ""
			}
			piece := runewidth.Truncate(word, width, "")
			if piece == "" {
				_, size := utf8.DecodeRuneInString(word)
				piece = "…"
				word = word[size:]
			} else {
				word = strings.TrimPrefix(word, piece)
			}
			lines = append(lines, piece)
		}
		if word == "" {
			continue
		}
		if line == "" {
			line = word
			continue
		}
		if dashboardDisplayWidth(line)+1+dashboardDisplayWidth(word) <= width {
			line += " " + word
			continue
		}
		lines = append(lines, line)
		line = word
	}
	if line != "" {
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return []string{""}
	}
	return lines
}

func truncateDashboardText(value string, width int) string {
	if width < 1 {
		return ""
	}
	value = safeText(value)
	if dashboardDisplayWidth(value) <= width {
		return value
	}
	if width == 1 {
		return "…"
	}
	return runewidth.Truncate(value, width-1, "") + "…"
}

func padDashboardText(value string, width int) string {
	padding := width - dashboardDisplayWidth(value)
	if padding <= 0 {
		return value
	}
	return value + strings.Repeat(" ", padding)
}

func dashboardDisplayWidth(value string) int {
	return runewidth.StringWidth(stripDashboardANSI(value))
}

func stripDashboardANSI(value string) string {
	for {
		start := strings.Index(value, "\x1b[")
		if start < 0 {
			return value
		}
		end := strings.Index(value[start:], "m")
		if end < 0 {
			return value[:start]
		}
		value = value[:start] + value[start+end+1:]
	}
}

func dashboardBorder(value string, color bool) string {
	if !color {
		return value
	}
	return paint(value, "38;5;31", "", "")
}

func dashboardTitle(value string, color bool) string {
	if !color {
		return value
	}
	return paint(value, "38;5;81", "", "1")
}

func dashboardLabel(value string, color bool) string {
	if !color {
		return value
	}
	return paint(value, "38;5;110", "", "1")
}

func styleDashboardBadge(value string, tone dashboardBadgeTone, color bool) string {
	if !color {
		return value
	}
	switch tone {
	case badgeConstraint:
		return paint(value, "38;5;220", "", "1")
	default:
		return paint(value, "38;5;42", "", "1")
	}
}
