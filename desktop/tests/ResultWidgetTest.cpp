#include "AdvancedDialog.h"
#include "ResultWidget.h"

#include <QJsonArray>
#include <QJsonObject>
#include <QPlainTextEdit>
#include <QHeaderView>
#include <QPushButton>
#include <QSettings>
#include <QTableWidget>
#include <QTabWidget>
#include <QTreeWidget>
#include <QtTest>

class ResultWidgetTest final : public QObject
{
    Q_OBJECT

private slots:
    void displaysTargetAndDNS();
    void displaysSchemaV5WorkbenchTabs();
    void displaysInvestigationStackAndRelatedTabs();
    void serializesResearchLinkSelection();
    void wrapsAndRemembersAdjustableColumns();
    void deduplicatesEquivalentTimelineAndDNSRows();
    void showsResolverAgreementAndRawSource();
};

void ResultWidgetTest::serializesResearchLinkSelection()
{
    AdvancedDialog dialog;
    dialog.setInvestigationLinkProviders(QJsonArray{
        QJsonObject{{QStringLiteral("id"), QStringLiteral("otx")},
                    {QStringLiteral("label"), QStringLiteral("AlienVault OTX")},
                    {QStringLiteral("purpose"), QStringLiteral("Threat context")},
                    {QStringLiteral("tier"), QStringLiteral("core")},
                    {QStringLiteral("targets"), QJsonArray{QStringLiteral("domain"), QStringLiteral("ipv4")}}},
    });
    dialog.setOptions(QJsonObject{{QStringLiteral("investigation"), QJsonObject{
        {QStringLiteral("link_providers"), QJsonArray{QStringLiteral("all")}},
    }}});
    QCOMPARE(dialog.options().value(QStringLiteral("investigation")).toObject()
                 .value(QStringLiteral("link_providers")).toArray().first().toString(), QStringLiteral("all"));

    dialog.setOptions(QJsonObject{{QStringLiteral("investigation"), QJsonObject{
        {QStringLiteral("external_link_template"), QStringLiteral("off")},
    }}});
    const QJsonObject disabled = dialog.options().value(QStringLiteral("investigation")).toObject();
    QCOMPARE(disabled.value(QStringLiteral("external_link_template")).toString(), QStringLiteral("off"));
    QVERIFY(!disabled.contains(QStringLiteral("link_providers")));
}

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

void ResultWidgetTest::displaysSchemaV5WorkbenchTabs()
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
        {QStringLiteral("schema_version"), 5},
        {QStringLiteral("operation"), QStringLiteral("diagnose")},
        {QStringLiteral("subject"), QJsonObject{{QStringLiteral("canonical"), QStringLiteral("example.com")},
                                                  {QStringLiteral("kind"), QStringLiteral("registrable_domain")}}},
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

void ResultWidgetTest::displaysInvestigationStackAndRelatedTabs()
{
    ResultWidget widget;
    widget.setInvestigationLinkProviders(QJsonArray{
        QJsonObject{{QStringLiteral("label"), QStringLiteral("BuiltWith")},
                    {QStringLiteral("purpose"), QStringLiteral("Technology profile")}},
        QJsonObject{{QStringLiteral("label"), QStringLiteral("Shodan")},
                    {QStringLiteral("purpose"), QStringLiteral("Observed services")}},
    });
    const QJsonObject evidence{{QStringLiteral("source"), QStringLiteral("http")},
                               {QStringLiteral("field"), QStringLiteral("homepage markup")},
                               {QStringLiteral("value"), QStringLiteral("WordPress asset paths")}};
    const QJsonObject component{{QStringLiteral("category"), QStringLiteral("web_application")},
                                {QStringLiteral("name"), QStringLiteral("WordPress")},
                                {QStringLiteral("role"), QStringLiteral("CMS")},
                                {QStringLiteral("confidence"), QStringLiteral("high")},
                                {QStringLiteral("summary"), QStringLiteral("WordPress was identified from public homepage markup.")},
                                {QStringLiteral("evidence"), QJsonArray{evidence}}};
    const QJsonObject related{{QStringLiteral("provider"), QStringLiteral("otx")},
                              {QStringLiteral("hostname"), QStringLiteral("neighbor.example")},
                              {QStringLiteral("address"), QStringLiteral("192.0.2.1")},
                              {QStringLiteral("current"), QStringLiteral("stale")}};
    const QJsonObject domainLink{{QStringLiteral("label"), QStringLiteral("BuiltWith")},
                                 {QStringLiteral("type"), QStringLiteral("domain")},
                                 {QStringLiteral("value"), QStringLiteral("example.com")},
                                 {QStringLiteral("url"), QStringLiteral("https://builtwith.com/example.com")}};
    const QJsonObject ipLink{{QStringLiteral("label"), QStringLiteral("Shodan")},
                             {QStringLiteral("type"), QStringLiteral("ip")},
                             {QStringLiteral("value"), QStringLiteral("192.0.2.1")},
                             {QStringLiteral("url"), QStringLiteral("https://www.shodan.io/host/192.0.2.1")}};
    const QJsonObject network{{QStringLiteral("address"), QStringLiteral("192.0.2.1")},
                              {QStringLiteral("provider"), QStringLiteral("Example Network")},
                              {QStringLiteral("links"), QJsonArray{ipLink}}};
    const QJsonObject investigation{{QStringLiteral("domain"), QStringLiteral("example.com")},
                                    {QStringLiteral("summary"), QStringLiteral("Web: WordPress")},
                                    {QStringLiteral("components"), QJsonArray{component}},
                                    {QStringLiteral("networks"), QJsonArray{network}},
                                    {QStringLiteral("links"), QJsonArray{domainLink}},
                                    {QStringLiteral("related"), QJsonArray{related}},
                                    {QStringLiteral("related_total"), 7}};
    const QJsonObject report{{QStringLiteral("schema_version"), 5},
                             {QStringLiteral("operation"), QStringLiteral("investigate")},
                             {QStringLiteral("subject"), QJsonObject{{QStringLiteral("canonical"), QStringLiteral("example.com")}}},
                             {QStringLiteral("investigation"), investigation}};
    widget.setReportItem(QJsonObject{{QStringLiteral("input"), QStringLiteral("example.com")},
                                     {QStringLiteral("report"), report}});

    QCOMPARE(widget.relatedRowCount(), 1);
    QTreeWidget *stack = widget.findChild<QTreeWidget *>(QStringLiteral("stackTree"));
    QVERIFY(stack);
    QCOMPARE(stack->columnCount(), 4);
    QVERIFY(stack->topLevelItemCount() >= 1);
    QTreeWidgetItem *technology = nullptr;
    for (int group = 0; group < stack->topLevelItemCount(); ++group) {
        for (int row = 0; row < stack->topLevelItem(group)->childCount(); ++row) {
            QTreeWidgetItem *candidate = stack->topLevelItem(group)->child(row);
            if (candidate->text(1) == QStringLiteral("WordPress"))
                technology = candidate;
        }
    }
    QVERIFY(technology);
    QCOMPARE(technology->childCount(), 0);
    stack->setCurrentItem(technology);
    QCoreApplication::processEvents();
    const QTableWidget *evidenceTable = widget.findChild<QTableWidget *>(QStringLiteral("stackEvidenceTable"));
    QVERIFY(evidenceTable);
    QCOMPARE(evidenceTable->rowCount(), 1);
    QCOMPARE(evidenceTable->item(0, 3)->text(), QStringLiteral("WordPress asset paths"));
    for (int group = 0; group < stack->topLevelItemCount(); ++group)
        QVERIFY(stack->topLevelItem(group)->text(0) != QStringLiteral("Investigation links"));

    QTreeWidget *research = widget.findChild<QTreeWidget *>(QStringLiteral("researchTree"));
    QVERIFY(research);
    QCOMPARE(research->topLevelItemCount(), 2);
    QCOMPARE(research->topLevelItem(0)->text(0), QStringLiteral("Domain — example.com"));
    QCOMPARE(research->topLevelItem(0)->child(0)->text(0), QStringLiteral("BuiltWith"));
    QCOMPARE(research->topLevelItem(0)->child(0)->text(1), QStringLiteral("Technology profile"));
    research->setCurrentItem(research->topLevelItem(1)->child(0));
    QCoreApplication::processEvents();
    const QPushButton *openResearch = widget.findChild<QPushButton *>(QStringLiteral("openResearchButton"));
    const QPushButton *copyResearch = widget.findChild<QPushButton *>(QStringLiteral("copyResearchButton"));
    QVERIFY(openResearch && openResearch->isEnabled());
    QVERIFY(copyResearch && copyResearch->isEnabled());

    const QTreeWidget *overview = widget.findChild<QTreeWidget *>(QStringLiteral("overviewTree"));
    QVERIFY(overview);
    QVERIFY(overview->topLevelItemCount() >= 2);
    QCOMPARE(overview->topLevelItem(1)->text(0), QStringLiteral("Technology & infrastructure"));
    QCOMPARE(overview->topLevelItem(1)->child(0)->text(0), QStringLiteral("Web technology"));
    QCOMPARE(overview->topLevelItem(1)->child(0)->text(1), QStringLiteral("WordPress"));
    const QTabWidget *tabs = widget.findChild<QTabWidget *>();
    QVERIFY(tabs);
    for (const QString &name : {QStringLiteral("Stack"), QStringLiteral("Research"), QStringLiteral("Related")}) {
        int index = -1;
        for (int candidate = 0; candidate < tabs->count(); ++candidate) {
            if (tabs->tabText(candidate) == name)
                index = candidate;
        }
        QVERIFY(index >= 0);
        QVERIFY(tabs->isTabVisible(index));
    }
    QCOMPARE(tabs->tabText(tabs->currentIndex()), QStringLiteral("Overview"));
}

void ResultWidgetTest::wrapsAndRemembersAdjustableColumns()
{
    QSettings settings;
    settings.remove(QStringLiteral("result/layout-v1/dns"));
    {
        ResultWidget widget;
        QCoreApplication::processEvents();
        const QTreeWidget *overview = widget.findChild<QTreeWidget *>(QStringLiteral("overviewTree"));
        const QTableWidget *dns = widget.findChild<QTableWidget *>(QStringLiteral("dnsTable"));
        QVERIFY(overview);
        QVERIFY(dns);
        QVERIFY(overview->wordWrap());
        QCOMPARE(overview->textElideMode(), Qt::ElideNone);
        QCOMPARE(overview->header()->sectionResizeMode(0), QHeaderView::Interactive);
        QVERIFY(dns->wordWrap());
        QCOMPARE(dns->textElideMode(), Qt::ElideNone);
        QCOMPARE(dns->horizontalHeader()->sectionResizeMode(3), QHeaderView::Interactive);
        dns->horizontalHeader()->resizeSection(3, 137);
        QCOMPARE(dns->horizontalHeader()->sectionSize(3), 137);
        QTest::qWait(100);
    }
    settings.sync();
    {
        ResultWidget widget;
        const QTableWidget *dns = widget.findChild<QTableWidget *>(QStringLiteral("dnsTable"));
        QVERIFY(dns);
        QCOMPARE(dns->horizontalHeader()->sectionSize(3), 137);
    }
    settings.remove(QStringLiteral("result/layout-v1/dns"));
}

void ResultWidgetTest::deduplicatesEquivalentTimelineAndDNSRows()
{
    ResultWidget widget;
    const QJsonObject firstRecord{{QStringLiteral("type"), QStringLiteral("CNAME")},
                                  {QStringLiteral("name"), QStringLiteral("webmail.example.com")},
                                  {QStringLiteral("ttl"), 154},
                                  {QStringLiteral("value"), QStringLiteral("mail.example.com")}};
    QJsonObject agedRecord = firstRecord;
    agedRecord.insert(QStringLiteral("ttl"), 155);
    QJsonObject distinctRecord = firstRecord;
    distinctRecord.insert(QStringLiteral("value"), QStringLiteral("backup.example.com"));

    const QJsonArray events{
        QJsonObject{{QStringLiteral("action"), QStringLiteral("registration")}, {QStringLiteral("date"), QStringLiteral("2026-02-21T05:13:38Z")}},
        QJsonObject{{QStringLiteral("action"), QStringLiteral("Registration")}, {QStringLiteral("date"), QStringLiteral("2026-02-21T05:13:38+00:00")}},
        QJsonObject{{QStringLiteral("action"), QStringLiteral("expiration")}, {QStringLiteral("date"), QStringLiteral("2027-02-21T05:13:38Z")}},
        QJsonObject{{QStringLiteral("action"), QStringLiteral("registrar expiration")}, {QStringLiteral("date"), QStringLiteral("2027-02-21T05:13:38+00:00")}},
        QJsonObject{{QStringLiteral("action"), QStringLiteral("registrar expiration")}, {QStringLiteral("date"), QStringLiteral("2028-02-21T05:13:38Z")}},
        QJsonObject{{QStringLiteral("action"), QStringLiteral("last changed")}, {QStringLiteral("date"), QStringLiteral("2026-02-21T05:15:48Z")}},
        QJsonObject{{QStringLiteral("action"), QStringLiteral("changed")}, {QStringLiteral("date"), QStringLiteral("2026-02-21T05:15:48+00:00")}},
        QJsonObject{{QStringLiteral("action"), QStringLiteral("last update of RDAP database")}, {QStringLiteral("date"), QStringLiteral("2026-08-11T03:19:33Z")}},
        QJsonObject{{QStringLiteral("action"), QStringLiteral("last update of RDAP database")}, {QStringLiteral("date"), QStringLiteral("2026-02-21T05:13:38+00:00")}},
        QJsonObject{{QStringLiteral("action"), QStringLiteral("transfer")}, {QStringLiteral("date"), QStringLiteral("2026-02-21T05:13:38.123400Z")}},
        QJsonObject{{QStringLiteral("action"), QStringLiteral("transfer")}, {QStringLiteral("date"), QStringLiteral("2026-02-21T05:13:38.123499Z")}},
    };
    const QJsonObject result{
        {QStringLiteral("query"), QJsonObject{{QStringLiteral("canonical"), QStringLiteral("example.com")}}},
        {QStringLiteral("route"), QJsonObject{{QStringLiteral("protocol"), QStringLiteral("rdap")}}},
        {QStringLiteral("object"), QJsonObject{{QStringLiteral("name"), QStringLiteral("example.com")}, {QStringLiteral("events"), events}}},
        {QStringLiteral("dns"), QJsonObject{{QStringLiteral("records"), QJsonArray{firstRecord, agedRecord, distinctRecord}}}},
    };
    widget.setItem(QJsonObject{{QStringLiteral("input"), QStringLiteral("example.com")}, {QStringLiteral("result"), result}});
    QCOMPARE(widget.dnsRowCount(), 2);

    const QTreeWidget *overview = widget.findChild<QTreeWidget *>(QStringLiteral("overviewTree"));
    QVERIFY(overview);
    QTreeWidgetItem *timeline = nullptr;
    for (int row = 0; row < overview->topLevelItemCount(); ++row) {
        if (overview->topLevelItem(row)->text(0) == QStringLiteral("Timeline")) {
            timeline = overview->topLevelItem(row);
            break;
        }
    }
    QVERIFY(timeline);
    QCOMPARE(timeline->childCount(), 5);
    int databaseRows = 0;
    int transferRows = 0;
    for (int row = 0; row < timeline->childCount(); ++row) {
        const QTreeWidgetItem *event = timeline->child(row);
        if (event->text(0) == QStringLiteral("RDAP database updated")) {
            ++databaseRows;
            QCOMPARE(event->text(1), QStringLiteral("2026-08-11T03:19:33Z"));
        }
        if (event->text(0) == QStringLiteral("transfer")) {
            ++transferRows;
            QVERIFY(event->text(1).contains(QStringLiteral(".123499Z")));
        }
    }
    QCOMPARE(databaseRows, 1);
    QCOMPARE(transferRows, 1);
}

void ResultWidgetTest::showsResolverAgreementAndRawSource()
{
    ResultWidget widget;
    const QJsonArray messages{
        QJsonObject{{QStringLiteral("name"), QStringLiteral("example.com")},
                    {QStringLiteral("type"), QStringLiteral("A")},
                    {QStringLiteral("class"), QStringLiteral("IN")},
                    {QStringLiteral("resolver"), QStringLiteral("system")},
                    {QStringLiteral("rcode"), QStringLiteral("NOERROR")},
                    {QStringLiteral("transport"), QStringLiteral("udp")}},
        QJsonObject{{QStringLiteral("name"), QStringLiteral("example.com")},
                    {QStringLiteral("type"), QStringLiteral("A")},
                    {QStringLiteral("class"), QStringLiteral("IN")},
                    {QStringLiteral("resolver"), QStringLiteral("authoritative://192.0.2.53:53")},
                    {QStringLiteral("rcode"), QStringLiteral("NOERROR")},
                    {QStringLiteral("transport"), QStringLiteral("udp")}},
    };
    const QJsonObject report{
        {QStringLiteral("schema_version"), 5},
        {QStringLiteral("operation"), QStringLiteral("dns.compare")},
        {QStringLiteral("subject"), QJsonObject{{QStringLiteral("canonical"), QStringLiteral("example.com")}}},
        {QStringLiteral("dns"), QJsonObject{{QStringLiteral("mode"), QStringLiteral("compare")},
                                             {QStringLiteral("messages"), messages}}},
    };
    const QString raw = QStringLiteral("Domain Name: EXAMPLE.COM\n");
    const QJsonArray rawSources{QJsonObject{{QStringLiteral("protocol"), QStringLiteral("whois")},
                                            {QStringLiteral("endpoint"), QStringLiteral("whois.example")},
                                            {QStringLiteral("content"), raw}}};
    widget.setReportItem(QJsonObject{{QStringLiteral("input"), QStringLiteral("example.com")},
                                     {QStringLiteral("report"), report},
                                     {QStringLiteral("raw_sources"), rawSources}});

    const QTabWidget *tabs = widget.findChild<QTabWidget *>();
    QVERIFY(tabs);
    int compareIndex = -1;
    for (int index = 0; index < tabs->count(); ++index) {
        if (tabs->tabText(index) == QStringLiteral("Compare")) {
            compareIndex = index;
            break;
        }
    }
    QVERIFY(compareIndex >= 0);
    QVERIFY(tabs->isTabVisible(compareIndex));
    auto *comparison = qobject_cast<QTableWidget *>(tabs->widget(compareIndex));
    QVERIFY(comparison);
    QCOMPARE(comparison->rowCount(), 2);
    QCOMPARE(comparison->item(0, 2)->text(), QStringLiteral("Agrees"));
    QCOMPARE(comparison->item(1, 2)->text(), QStringLiteral("Agrees"));
    QVERIFY(widget.hasRawSource());
    QCOMPARE(widget.currentRawSource(), raw);
}

QTEST_MAIN(ResultWidgetTest)
#include "ResultWidgetTest.moc"
