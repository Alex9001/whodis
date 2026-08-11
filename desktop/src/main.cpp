#include "MainWindow.h"

#include "Appearance.h"

#include <QApplication>
#include <QCoreApplication>
#include <QIcon>
#include <QSettings>
#include <QStyle>
#include <QStyleHints>

namespace {

bool prefersDarkAppearance(const QApplication &application)
{
#ifdef Q_OS_WIN
    // Qt's Windows style can retain a light palette even when applications are
    // configured to use the dark theme, so read the same user preference that
    // native Windows applications use.
    QSettings theme(QStringLiteral("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize"),
                    QSettings::NativeFormat);
    const QVariant appsUseLightTheme = theme.value(QStringLiteral("AppsUseLightTheme"));
    if (appsUseLightTheme.isValid())
        return appsUseLightTheme.toInt() == 0;
#endif

#if QT_VERSION >= QT_VERSION_CHECK(6, 5, 0)
    const Qt::ColorScheme scheme = application.styleHints()->colorScheme();
    if (scheme != Qt::ColorScheme::Unknown)
        return scheme == Qt::ColorScheme::Dark;
#endif

    const QColor window = application.palette().color(QPalette::Active, QPalette::Window);
    return window.lightnessF() < 0.5;
}

void applyAppearance(QApplication &application)
{
    const QPalette palette = Appearance::themedPalette(application.style()->standardPalette(),
                                                        prefersDarkAppearance(application));
    application.setPalette(palette);
    application.setStyleSheet(Appearance::professionalChromeStyleSheet(palette));
}

} // namespace

int main(int argc, char *argv[])
{
    QApplication application(argc, argv);
    QCoreApplication::setOrganizationName(QStringLiteral("Cyberbrand"));
    QCoreApplication::setOrganizationDomain(QStringLiteral("cyberbrand.net"));
    QCoreApplication::setApplicationName(QStringLiteral("Whodis"));
    QCoreApplication::setApplicationVersion(QStringLiteral(WHODIS_GUI_VERSION));
    applyAppearance(application);
#if QT_VERSION >= QT_VERSION_CHECK(6, 5, 0)
    QObject::connect(application.styleHints(), &QStyleHints::colorSchemeChanged, &application,
                     [&application](Qt::ColorScheme) { applyAppearance(application); });
#endif
    application.setWindowIcon(QIcon(QStringLiteral(":/icons/whodis.png")));

    MainWindow window;
    window.show();
    return application.exec();
}
