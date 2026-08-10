#include "Appearance.h"

#include <QtTest>

class AppearanceTest final : public QObject
{
    Q_OBJECT

private slots:
    void controlsAreReadable_data();
    void controlsAreReadable();
    void chromeStyleUsesProfessionalPalette();
};

void AppearanceTest::controlsAreReadable_data()
{
    QTest::addColumn<QColor>("window");
    QTest::addColumn<QColor>("base");
    QTest::addColumn<QColor>("button");

    QTest::newRow("light") << QColor(QStringLiteral("#f5f7fa"))
                           << QColor(QStringLiteral("#ffffff"))
                           << QColor(QStringLiteral("#e5e7eb"));
    QTest::newRow("dark") << QColor(QStringLiteral("#191919"))
                          << QColor(QStringLiteral("#141414"))
                          << QColor(QStringLiteral("#25282d"));
}

void AppearanceTest::controlsAreReadable()
{
    QFETCH(QColor, window);
    QFETCH(QColor, base);
    QFETCH(QColor, button);

    QPalette palette;
    for (const QPalette::ColorGroup group : {QPalette::Active, QPalette::Inactive, QPalette::Disabled}) {
        palette.setColor(group, QPalette::Window, window);
        palette.setColor(group, QPalette::Base, base);
        palette.setColor(group, QPalette::Button, button);
        palette.setColor(group, QPalette::WindowText, QColor(QStringLiteral("#202020")));
        palette.setColor(group, QPalette::Text, QColor(QStringLiteral("#202020")));
        palette.setColor(group, QPalette::ButtonText, QColor(QStringLiteral("#202020")));
    }
    palette.setColor(QPalette::Active, QPalette::Highlight, QColor(QStringLiteral("#00ffff")));

    const QPalette adjusted = Appearance::professionalPalette(palette);
    for (const QPalette::ColorGroup group : {QPalette::Active, QPalette::Inactive, QPalette::Disabled}) {
        QVERIFY(Appearance::contrastRatio(adjusted.color(group, QPalette::WindowText), window)
                >= Appearance::MinimumTextContrast);
        QVERIFY(Appearance::contrastRatio(adjusted.color(group, QPalette::Text), base)
                >= Appearance::MinimumTextContrast);
        QVERIFY(Appearance::contrastRatio(adjusted.color(group, QPalette::ButtonText), button)
                >= Appearance::MinimumTextContrast);
        QVERIFY(Appearance::contrastRatio(adjusted.color(group, QPalette::HighlightedText),
                                          adjusted.color(group, QPalette::Highlight))
                >= Appearance::MinimumTextContrast);
    }

    const double hoverSeparation = Appearance::contrastRatio(
        adjusted.color(QPalette::Active, QPalette::Highlight), window);
    QVERIFY(hoverSeparation >= Appearance::MinimumHoverSeparation);
    QVERIFY(hoverSeparation <= Appearance::MaximumHoverSeparation);
    QVERIFY(adjusted.color(QPalette::Active, QPalette::Highlight) != QColor(QStringLiteral("#00ffff")));

    QCOMPARE(adjusted.color(QPalette::Active, QPalette::Window), window);
    QCOMPARE(adjusted.color(QPalette::Active, QPalette::Base), base);
    QCOMPARE(adjusted.color(QPalette::Active, QPalette::Button), button);
}

void AppearanceTest::chromeStyleUsesProfessionalPalette()
{
    QPalette palette;
    palette.setColor(QPalette::Active, QPalette::WindowText, QColor(QStringLiteral("#e4ebf1")));
    palette.setColor(QPalette::Disabled, QPalette::WindowText, QColor(QStringLiteral("#aab5bf")));
    palette.setColor(QPalette::Active, QPalette::HighlightedText, QColor(QStringLiteral("#f4fbff")));
    palette.setColor(QPalette::Active, QPalette::Highlight, QColor(QStringLiteral("#214b5a")));

    const QString style = Appearance::professionalChromeStyleSheet(palette);
    QVERIFY(style.contains(QStringLiteral("QMenuBar::item:selected")));
    QVERIFY(style.contains(QStringLiteral("QMenu::item:selected")));
    QVERIFY(style.contains(QStringLiteral("QToolBar QToolButton:hover")));
    QVERIFY(style.contains(QStringLiteral("color: #e4ebf1")));
    QVERIFY(style.contains(QStringLiteral("color: #aab5bf")));
    QVERIFY(style.contains(QStringLiteral("color: #f4fbff")));
    QVERIFY(style.contains(QStringLiteral("background: #214b5a")));
}

QTEST_MAIN(AppearanceTest)
#include "AppearanceTest.moc"
