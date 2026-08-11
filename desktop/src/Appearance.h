#pragma once

#include <QPalette>
#include <QString>

namespace Appearance {

inline constexpr double MinimumTextContrast = 4.5;
inline constexpr double MinimumHoverSeparation = 1.15;
inline constexpr double MaximumHoverSeparation = 3.0;

double contrastRatio(const QColor &foreground, const QColor &background);
QPalette themedPalette(const QPalette &palette, bool darkMode);
QPalette professionalPalette(const QPalette &palette);
QString professionalChromeStyleSheet(const QPalette &palette);

} // namespace Appearance
