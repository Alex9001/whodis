package whodis

import (
	"io"
	"strings"

	"github.com/mattn/go-runewidth"
)

const (
	maximumGeekBoysWidth = 86
	geekBoysColumnWidth  = 80
	geekBoysColumnGap    = 2
	geekBoysBorderWidth  = 20
)

// renderGeekBoys renders the semantic dashboard data as a compact, old-web
// inspired ASCII layout. Color is deliberately ignored: this format is useful
// in terminals, logs, mail, and other places where ANSI escapes are unwelcome.
func renderGeekBoys(writer io.Writer, result LookupResult, options RenderOptions) string {
	width := dashboardWidth(writer, options.Width)
	if width > maximumGeekBoysWidth {
		width = maximumGeekBoysWidth
	}
	if width < 1 {
		width = 1
	}

	view := buildDashboard(result, options.Details)
	panels := append([]dashboardPanel(nil), view.panels...)
	if view.details != nil {
		panels = append(panels, *view.details)
	}
	return strings.Join(renderGeekBoysLayout(panels, width), "\n") + "\n"
}

func renderGeekBoysLayout(panels []dashboardPanel, width int) []string {
	if width < geekBoysColumnWidth || len(panels) < 2 {
		lines := make([]string, 0)
		for index, panel := range panels {
			if index > 0 {
				lines = append(lines, "")
			}
			lines = append(lines, renderGeekBoysPanel(panel, width)...)
		}
		return lines
	}

	available := width - geekBoysColumnGap
	widths := []int{available / 2, available - available/2}
	columns := assignGeekBoysPanels(panels, widths)
	rendered := make([][]string, len(columns))
	maximumHeight := 0
	for columnIndex, column := range columns {
		for panelIndex, panel := range column {
			if panelIndex > 0 {
				rendered[columnIndex] = append(rendered[columnIndex], "")
			}
			rendered[columnIndex] = append(rendered[columnIndex], renderGeekBoysPanel(panel, widths[columnIndex])...)
		}
		if len(rendered[columnIndex]) > maximumHeight {
			maximumHeight = len(rendered[columnIndex])
		}
	}

	lines := make([]string, 0, maximumHeight)
	for lineIndex := 0; lineIndex < maximumHeight; lineIndex++ {
		var line strings.Builder
		for columnIndex := range rendered {
			if columnIndex > 0 {
				line.WriteString(strings.Repeat(" ", geekBoysColumnGap))
			}
			value := ""
			if lineIndex < len(rendered[columnIndex]) {
				value = rendered[columnIndex][lineIndex]
			}
			line.WriteString(padDashboardText(value, widths[columnIndex]))
		}
		lines = append(lines, strings.TrimRight(line.String(), " "))
	}
	return lines
}

// assignGeekBoysPanels uses a largest-first masonry pass. The primary object
// panel remains at the top left so the output always starts with the lookup
// itself; the remaining panels are placed where they keep the columns shortest.
func assignGeekBoysPanels(panels []dashboardPanel, widths []int) [][]dashboardPanel {
	columns := make([][]dashboardPanel, len(widths))
	heights := make([]int, len(widths))
	placed := make([]bool, len(panels))
	place := func(panelIndex, columnIndex int) {
		if len(columns[columnIndex]) > 0 {
			heights[columnIndex]++
		}
		panel := panels[panelIndex]
		columns[columnIndex] = append(columns[columnIndex], panel)
		heights[columnIndex] += len(renderGeekBoysPanel(panel, widths[columnIndex]))
		placed[panelIndex] = true
	}

	primary := 0
	for index, panel := range panels {
		if panel.role == panelPrimary {
			primary = index
			break
		}
	}
	if len(panels) > 0 {
		place(primary, 0)
	}

	for {
		next, nextHeight := -1, -1
		for index, panel := range panels {
			if placed[index] {
				continue
			}
			height := 0
			for _, width := range widths {
				height = max(height, len(renderGeekBoysPanel(panel, width)))
			}
			if height > nextHeight {
				next, nextHeight = index, height
			}
		}
		if next < 0 {
			break
		}

		target := 0
		for columnIndex := 1; columnIndex < len(columns); columnIndex++ {
			if heights[columnIndex] < heights[target] {
				target = columnIndex
			}
		}
		place(next, target)
	}
	return columns
}

func renderGeekBoysPanel(panel dashboardPanel, width int) []string {
	if width < geekBoysBorderWidth {
		lines := geekBoysWrap(geekBoysPanelTitle(panel.title), width)
		return append(lines, renderGeekBoysBody(panel, width)...)
	}

	innerWidth := width - 4
	title := geekBoysClip(geekBoysPanelTitle(panel.title), width-7)
	prefix := ".--- " + title + " "
	top := prefix + strings.Repeat("-", max(0, width-dashboardDisplayWidth(prefix)-1)) + "+"
	lines := []string{top}
	for _, bodyLine := range renderGeekBoysBody(panel, innerWidth) {
		lines = append(lines, "| "+padDashboardText(bodyLine, innerWidth)+" |")
	}
	lines = append(lines, "+"+strings.Repeat("-", width-2)+"'")
	return lines
}

func renderGeekBoysBody(panel dashboardPanel, width int) []string {
	if width < 1 {
		width = 1
	}
	switch panel.kind {
	case panelDNS:
		lines := renderGeekBoysRows(panel.rows, width)
		if len(panel.items) > 0 {
			if len(lines) > 0 {
				lines = append(lines, "")
			}
			lines = append(lines, renderGeekBoysItems(panel.items, width)...)
		}
		return lines
	case panelNotices:
		return renderGeekBoysNotices(panel.notices, width)
	default:
		lines := renderGeekBoysBadges(panel.badges, width)
		if len(lines) > 0 && len(panel.rows) > 0 {
			lines = append(lines, "")
		}
		return append(lines, renderGeekBoysRows(panel.rows, width)...)
	}
}

func renderGeekBoysBadges(badges []dashboardBadge, width int) []string {
	lines := make([]string, 0, len(badges))
	current, currentWidth := "", 0
	flush := func() {
		if current != "" {
			lines = append(lines, current)
			current, currentWidth = "", 0
		}
	}
	for _, badge := range badges {
		text := safeText(badge.text)
		if text == "" {
			continue
		}
		if width < 5 || dashboardDisplayWidth(text)+4 > width {
			flush()
			if width < 5 {
				lines = append(lines, geekBoysWrap(text, width)...)
				continue
			}
			for _, chunk := range geekBoysWrap(text, width-4) {
				lines = append(lines, "+ "+chunk+" +")
			}
			continue
		}

		token := "+ " + text + " +"
		separatorWidth := 0
		if current != "" {
			separatorWidth = 2
		}
		if currentWidth+separatorWidth+dashboardDisplayWidth(token) > width {
			flush()
		}
		if current != "" {
			current += "  "
			currentWidth += 2
		}
		current += token
		currentWidth += dashboardDisplayWidth(token)
	}
	flush()
	return lines
}

func renderGeekBoysRows(rows []dashboardRow, width int) []string {
	if len(rows) == 0 {
		return nil
	}
	maximumLabel := 0
	for _, row := range rows {
		maximumLabel = max(maximumLabel, dashboardDisplayWidth(safeText(row.label)))
	}
	aligned := width >= 28 && maximumLabel <= 16 && width-maximumLabel-2 >= 12
	if aligned {
		valueWidth := width - maximumLabel - 2
		for _, row := range rows {
			if dashboardValueBenefitsFromStacking(row.value, valueWidth, max(1, width-2)) {
				aligned = false
				break
			}
		}
	}
	lines := make([]string, 0, len(rows))
	for _, row := range rows {
		label, value := safeText(row.label), safeText(row.value)
		if value == "" {
			continue
		}
		if aligned {
			valueWidth := width - maximumLabel - 2
			for index, chunk := range geekBoysWrap(value, valueWidth) {
				prefix := strings.Repeat(" ", maximumLabel) + "  "
				if index == 0 {
					prefix = padDashboardText(label, maximumLabel) + ": "
				}
				lines = append(lines, prefix+chunk)
			}
			continue
		}

		if label != "" {
			lines = append(lines, geekBoysWrap(label+":", width)...)
		}
		indent := 0
		if width > 2 {
			indent = 2
		}
		for _, chunk := range geekBoysWrap(value, max(1, width-indent)) {
			lines = append(lines, strings.Repeat(" ", indent)+chunk)
		}
	}
	return lines
}

func renderGeekBoysItems(items []string, width int) []string {
	items = uniqueFold(items)
	if len(items) == 0 {
		return nil
	}
	maximum := 0
	for _, item := range items {
		maximum = max(maximum, dashboardDisplayWidth(safeText(item)))
	}
	const gap = 2
	columns := (width + gap) / max(1, maximum+2+gap)
	if columns > 2 {
		columns = 2
	}
	if columns > len(items) {
		columns = len(items)
	}
	if columns < 2 {
		lines := make([]string, 0, len(items))
		for _, item := range items {
			prefix, continuation, contentWidth := "- ", "  ", width-2
			if width < 3 {
				prefix, continuation, contentWidth = "", "", width
			}
			for index, chunk := range geekBoysWrap(item, max(1, contentWidth)) {
				linePrefix := continuation
				if index == 0 {
					linePrefix = prefix
				}
				lines = append(lines, linePrefix+chunk)
			}
		}
		return lines
	}

	columnWidth := (width - gap) / 2
	lines := make([]string, 0, (len(items)+1)/2)
	for start := 0; start < len(items); start += 2 {
		var line strings.Builder
		for column := 0; column < 2; column++ {
			if column > 0 {
				line.WriteString(strings.Repeat(" ", gap))
			}
			value := ""
			if index := start + column; index < len(items) {
				value = "- " + safeText(items[index])
			}
			line.WriteString(padDashboardText(value, columnWidth))
		}
		lines = append(lines, strings.TrimRight(line.String(), " "))
	}
	return lines
}

func renderGeekBoysNotices(notices []dashboardNotice, width int) []string {
	lines := make([]string, 0)
	for noticeIndex, notice := range notices {
		if noticeIndex > 0 {
			lines = append(lines, "")
		}
		lines = append(lines, geekBoysWrap("Notice: "+firstNonEmpty(notice.title, "Registry notice"), width)...)
		for _, description := range notice.descriptions {
			lines = append(lines, renderGeekBoysPrefixed("- ", description, width)...)
		}
		for _, link := range notice.links {
			lines = append(lines, renderGeekBoysPrefixed("URL: ", link, width)...)
		}
	}
	return lines
}

func renderGeekBoysPrefixed(prefix, value string, width int) []string {
	prefixWidth := dashboardDisplayWidth(prefix)
	if width <= prefixWidth {
		return geekBoysWrap(value, width)
	}
	chunks := geekBoysWrap(value, width-prefixWidth)
	lines := make([]string, 0, len(chunks))
	for index, chunk := range chunks {
		linePrefix := strings.Repeat(" ", prefixWidth)
		if index == 0 {
			linePrefix = prefix
		}
		lines = append(lines, linePrefix+chunk)
	}
	return lines
}

func geekBoysPanelTitle(value string) string {
	return strings.ReplaceAll(safeText(value), "·", "-")
}

func geekBoysClip(value string, width int) string {
	if width < 1 {
		return ""
	}
	value = safeText(value)
	if dashboardDisplayWidth(value) <= width {
		return value
	}
	return runewidth.Truncate(value, width, "")
}

func geekBoysWrap(value string, width int) []string {
	if width < 1 {
		width = 1
	}
	value = safeText(value)
	if width == 1 {
		value = strings.Map(func(character rune) rune {
			if runewidth.RuneWidth(character) > 1 {
				return '?'
			}
			return character
		}, value)
	}
	return wrapDashboardText(value, width)
}
