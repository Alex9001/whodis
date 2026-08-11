#include "ResultWidget.h"

#include <QJsonArray>
#include <QJsonObject>
#include <QPlainTextEdit>
#include <QTabWidget>
#include <QtTest>

class ResultWidgetTest final : public QObject
{
    Q_OBJECT

private slots:
    void displaysTargetAndDNS();
    void displaysSchemaV3WorkbenchTabs();
};

void ResultWidgetTest::displaysTargetAndDNS()
{
    ResultWidget widget;
    const QJsonObject record{{QStringLiteral("type"), QStringLiteral("A")},
                             {QStringLiteral("name"), QStringLiteral("example.com")},
                             {QStringLiteral("ttl"), 300},
                             {QStringLiteral("value"), QStringLiteral("192.0.2.1")}};
    const QJsonObject result{{QStringLiteral("query"), QJsonObject{{QStringLiteral("canonical"), QStringLiteral("example.com")}}},
                             {QStringLiteral("route"), QJsonObject{{QStringLiteral("protocol"), QStringLiteral("rdap")}}},
                             {QStringLiteral("object"), QJsonObject{{QStringLiteral("name"), QStringLiteral("example.com")}}},
                             {QStringLiteral("dns"), QJsonObject{{QStringLiteral("records"), QJsonArray{record}}}}};
    const QJsonObject item{{QStringLiteral("input"), QStringLiteral("example.com")},
                           {QStringLiteral("result"), result}};
    widget.setItem(item);
    QCOMPARE(widget.currentTarget(), QStringLiteral("example.com"));
    QCOMPARE(widget.dnsRowCount(), 1);
    widget.showDNSTab();
    const QTabWidget *tabs = widget.findChild<QTabWidget *>();
    QVERIFY(tabs);
    QCOMPARE(tabs->tabText(tabs->currentIndex()), QStringLiteral("DNS"));
    QVERIFY(widget.copyText().contains(QStringLiteral("example.com")));

    const QPlainTextEdit *raw = widget.findChild<QPlainTextEdit *>();
    QVERIFY(raw);
    QCOMPARE(raw->lineWrapMode(), QPlainTextEdit::WidgetWidth);
    QCOMPARE(raw->horizontalScrollBarPolicy(), Qt::ScrollBarAlwaysOff);
}

void ResultWidgetTest::displaysSchemaV3WorkbenchTabs()
{
    ResultWidget widget;
    const QJsonObject record{{QStringLiteral("type"), QStringLiteral("MX")},
                             {QStringLiteral("name"), QStringLiteral("example.com")},
                             {QStringLiteral("ttl"), 300},
                             {QStringLiteral("value"), QStringLiteral("10 mail.example.com")}};
    const QJsonObject difference{{QStringLiteral("resolver"), QStringLiteral("udp://1.1.1.1")},
                                 {QStringLiteral("missing"), QJsonArray{QStringLiteral("A 192.0.2.1")}}};
    const QJsonObject hop{{QStringLiteral("zone"), QStringLiteral("com")},
                          {QStringLiteral("server"), QStringLiteral("192.0.2.53")},
                          {QStringLiteral("rcode"), QStringLiteral("NOERROR")}};
    const QJsonObject finding{{QStringLiteral("severity"), QStringLiteral("pass")},
                              {QStringLiteral("title"), QStringLiteral("DNS inventory")},
                              {QStringLiteral("summary"), QStringLiteral("Collected public DNS records.")}};
    const QJsonObject report{
        {QStringLiteral("schema_version"), 3},
        {QStringLiteral("operation"), QStringLiteral("diagnose")},
        {QStringLiteral("query"), QJsonObject{{QStringLiteral("canonical"), QStringLiteral("example.com")}}},
        {QStringLiteral("dns"), QJsonObject{{QStringLiteral("messages"), QJsonArray{QJsonObject{{QStringLiteral("answer"), QJsonArray{record}}}}},
                                             {QStringLiteral("differences"), QJsonArray{difference}}}},
        {QStringLiteral("diagnosis"), QJsonObject{{QStringLiteral("delegation"), QJsonObject{{QStringLiteral("trace"), QJsonArray{hop}}}},
                                                   {QStringLiteral("findings"), QJsonArray{finding}},
                                                   {QStringLiteral("http"), QJsonArray{QJsonObject{{QStringLiteral("url"), QStringLiteral("https://example.com")},
                                                                                                  {QStringLiteral("status"), 200}}}}}}};
    widget.setReportItem(QJsonObject{{QStringLiteral("input"), QStringLiteral("example.com")},
                                     {QStringLiteral("report"), report}});
    QCOMPARE(widget.currentTarget(), QStringLiteral("example.com"));
    QCOMPARE(widget.dnsRowCount(), 1);
    const QTabWidget *tabs = widget.findChild<QTabWidget *>();
    QVERIFY(tabs);
    for (const QString &name : {QStringLiteral("DNS"), QStringLiteral("Compare"), QStringLiteral("Delegation"), QStringLiteral("Services"), QStringLiteral("Findings")}) {
        int index = -1;
        for (int candidate = 0; candidate < tabs->count(); ++candidate) {
            if (tabs->tabText(candidate) == name) {
                index = candidate;
                break;
            }
        }
        QVERIFY2(index >= 0 && tabs->isTabVisible(index), qPrintable(name));
    }
}

QTEST_MAIN(ResultWidgetTest)
#include "ResultWidgetTest.moc"
