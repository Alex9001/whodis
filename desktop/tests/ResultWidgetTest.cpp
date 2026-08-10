#include "ResultWidget.h"

#include <QJsonArray>
#include <QJsonObject>
#include <QtTest>

class ResultWidgetTest final : public QObject
{
    Q_OBJECT

private slots:
    void displaysTargetAndDNS();
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
    QVERIFY(widget.copyText().contains(QStringLiteral("example.com")));
}

QTEST_MAIN(ResultWidgetTest)
#include "ResultWidgetTest.moc"
