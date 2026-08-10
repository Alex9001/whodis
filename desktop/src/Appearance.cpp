#include "Appearance.h"

#include <algorithm>
#include <cmath>

namespace {

double linearChannel(int channel)
{
    const double value = channel / 255.0;
    return value <= 0.04045 ? value / 12.92 : std::pow((value + 0.055) / 1.055, 2.4);
}

double luminance(const QColor &color)
{
    return 0.2126 * linearChannel(color.red())
        + 0.7152 * linearChannel(color.green())
        + 0.0722 * linearChannel(color.blue());
}

QColor blend(const QColor &foreground, const QColor &background, double foregroundWeight)
{
    const double backgroundWeight = 1.0 - foregroundWeight;
    return QColor(qRound(foreground.red() * foregroundWeight + background.red() * backgroundWeight),
                  qRound(foreground.green() * foregroundWeight + background.green() * backgroundWeight),
                  qRound(foreground.blue() * foregroundWeight + background.blue() * backgroundWeight));
}

QColor readableColor(const QColor &preferred, const QColor &background)
{
    if (Appearance::contrastRatio(preferred, background) >= Appearance::MinimumTextContrast)
        return preferred;
    const QColor black(QStringLiteral("#111820"));
    const QColor white(QStringLiteral("#f4f8fb"));
    return Appearance::contrastRatio(black, background) >= Appearance::contrastRatio(white, background) ? black : white;
}

QColor mutedReadableColor(const QColor &foreground, const QColor &background)
{
    for (double weight = 0.55; weight <= 1.0; weight += 0.02) {
        const QColor candidate = blend(foreground, background, weight);
        if (Appearance::contrastRatio(candidate, background) >= Appearance::MinimumTextContrast)
            return candidate;
    }
    return foreground;
}

} // namespace

namespace Appearance {

double contrastRatio(const QColor &foreground, const QColor &background)
{
    const double foregroundLuminance = luminance(foreground);
    const double backgroundLuminance = luminance(background);
    const double lighter = std::max(foregroundLuminance, backgroundLuminance);
    const double darker = std::min(foregroundLuminance, backgroundLuminance);
    return (lighter + 0.05) / (darker + 0.05);
}

QPalette professionalPalette(const QPalette &palette)
{
    QPalette adjusted = palette;
    const QColor window = palette.color(QPalette::Active, QPalette::Window);
    const QColor base = palette.color(QPalette::Active, QPalette::Base);
    const QColor button = palette.color(QPalette::Active, QPalette::Button);
    const bool dark = luminance(window) < 0.35;

    const QColor preferredText(dark ? QStringLiteral("#e4ebf1") : QStringLiteral("#1d2731"));
    const QColor preferredMuted(dark ? QStringLiteral("#aab5bf") : QStringLiteral("#596673"));
    const QColor preferredPlaceholder(dark ? QStringLiteral("#9ba8b4") : QStringLiteral("#66737f"));
    const QColor highlight(dark ? QStringLiteral("#214b5a") : QStringLiteral("#c9e7f0"));
    const QColor preferredHighlightedText(dark ? QStringLiteral("#f4fbff") : QStringLiteral("#14242b"));
    const QColor link(dark ? QStringLiteral("#55c2e6") : QStringLiteral("#006f91"));
    const QColor visitedLink(dark ? QStringLiteral("#9aa7ef") : QStringLiteral("#5d50a0"));

    const QColor windowText = readableColor(preferredText, window);
    const QColor text = readableColor(preferredText, base);
    const QColor buttonText = readableColor(preferredText, button);
    const QColor placeholderText = readableColor(preferredPlaceholder, base);
    const QColor highlightedText = readableColor(preferredHighlightedText, highlight);

    for (const QPalette::ColorGroup group : {QPalette::Active, QPalette::Inactive}) {
        adjusted.setColor(group, QPalette::WindowText, windowText);
        adjusted.setColor(group, QPalette::Text, text);
        adjusted.setColor(group, QPalette::ButtonText, buttonText);
        adjusted.setColor(group, QPalette::PlaceholderText, placeholderText);
        adjusted.setColor(group, QPalette::Highlight, highlight);
        adjusted.setColor(group, QPalette::HighlightedText, highlightedText);
        adjusted.setColor(group, QPalette::Link, link);
        adjusted.setColor(group, QPalette::LinkVisited, visitedLink);
    }

    adjusted.setColor(QPalette::Disabled, QPalette::WindowText,
                      mutedReadableColor(readableColor(preferredMuted, window), window));
    adjusted.setColor(QPalette::Disabled, QPalette::Text,
                      mutedReadableColor(readableColor(preferredMuted, base), base));
    adjusted.setColor(QPalette::Disabled, QPalette::ButtonText,
                      mutedReadableColor(readableColor(preferredMuted, button), button));
    adjusted.setColor(QPalette::Disabled, QPalette::PlaceholderText,
                      mutedReadableColor(readableColor(preferredMuted, base), base));
    adjusted.setColor(QPalette::Disabled, QPalette::Highlight, highlight);
    adjusted.setColor(QPalette::Disabled, QPalette::HighlightedText, highlightedText);
    return adjusted;
}

QString professionalChromeStyleSheet(const QPalette &palette)
{
    const QString normal = palette.color(QPalette::Active, QPalette::WindowText).name(QColor::HexRgb);
    const QString disabled = palette.color(QPalette::Disabled, QPalette::WindowText).name(QColor::HexRgb);
    const QString selected = palette.color(QPalette::Active, QPalette::HighlightedText).name(QColor::HexRgb);
    const QString highlight = palette.color(QPalette::Active, QPalette::Highlight).name(QColor::HexRgb);

    return QStringLiteral(
               "QMenuBar::item { color: %1; background: transparent; }"
               "QMenuBar::item:selected, QMenuBar::item:pressed { color: %2; background: %3; }"
               "QMenuBar::item:disabled { color: %4; background: transparent; }"
               "QMenu::item { color: %1; }"
               "QMenu::item:selected { color: %2; background: %3; }"
               "QMenu::item:disabled { color: %4; }"
               "QToolBar QToolButton { color: %1; }"
               "QToolBar QToolButton:hover, QToolBar QToolButton:pressed { color: %2; background: %3; }"
               "QToolBar QToolButton:disabled { color: %4; background: transparent; }")
        .arg(normal, selected, highlight, disabled);
}

} // namespace Appearance
