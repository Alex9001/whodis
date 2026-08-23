#include "ResultWidget.h"

#include "AdaptiveItemView.h"

#include <QComboBox>
#include <QClipboard>
#include <QDateTime>
#include <QDesktopServices>
#include <QGuiApplication>
#include <QHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonValue>
#include <QHBoxLayout>
#include <QLabel>
#include <QMenu>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSettings>
#include <QSplitter>
#include <QStackedLayout>
#include <QTableWidget>
#include <QTabWidget>
#include <QTreeWidget>
#include <QUrl>
#include <QVBoxLayout>

namespace {
constexpr int StackKindRole = Qt::UserRole;
constexpr int StackPayloadRole = Qt::UserRole + 1;

QString joined(const QJsonValue &value)
{
    if (value.isString())
        return value.toString();
    if (!value.isArray())
        return {};
    QStringList values;
    for (const QJsonValue &entry : value.toArray()) {
        if (entry.isString() && !entry.toString().isEmpty())
            values.append(entry.toString());
    }
    return values.join(QStringLiteral(", "));
}

void addValue(QTreeWidgetItem *parent, const QString &label, const QString &value)
{
    if (!value.trimmed().isEmpty())
        new QTreeWidgetItem(parent, {label, value});
}

QTreeWidgetItem *addGroup(QTreeWidget *tree, const QString &label)
{
    auto *group = new QTreeWidgetItem(tree, {label});
    QFont font = group->font(0);
    font.setBold(true);
    group->setFont(0, font);
    group->setFirstColumnSpanned(false);
    group->setExpanded(true);
    return group;
}

QTreeWidgetItem *addStackGroup(QTreeWidget *tree, const QString &label)
{
    QTreeWidgetItem *group = addGroup(tree, label);
    group->setFlags(group->flags() & ~Qt::ItemIsSelectable);
    return group;
}

void setStackPayload(QTreeWidgetItem *item, const QString &kind, const QJsonObject &payload)
{
    item->setData(0, StackKindRole, kind);
    item->setData(0, StackPayloadRole,
                  QString::fromUtf8(QJsonDocument(payload).toJson(QJsonDocument::Compact)));
}

QJsonObject stackPayload(const QTreeWidgetItem *item)
{
    if (!item)
        return {};
    return QJsonDocument::fromJson(item->data(0, StackPayloadRole).toString().toUtf8()).object();
}

void configureTable(QTableWidget *table, const QStringList &headers)
{
    table->setColumnCount(headers.size());
    table->setHorizontalHeaderLabels(headers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::ExtendedSelection);
    table->setSortingEnabled(true);
    table->setAlternatingRowColors(true);
}

QJsonObject reportDNS(const QJsonObject &report)
{
    QJsonObject dns = report.value(QStringLiteral("dns")).toObject();
    if (dns.isEmpty())
        dns = report.value(QStringLiteral("diagnosis")).toObject().value(QStringLiteral("dns")).toObject();
    return dns;
}

QJsonArray operationRecords(const QJsonObject &dns)
{
    QJsonArray records;
    QHash<QString, int> indexes;
    const auto append = [&records, &indexes](const QJsonArray &values) {
        for (const QJsonValue &value : values) {
            const QJsonObject record = value.toObject();
            QString name = record.value(QStringLiteral("name")).toString().trimmed().toLower();
            while (name.endsWith(QLatin1Char('.')))
                name.chop(1);
            const QString key = name + QLatin1Char('\0')
                + record.value(QStringLiteral("type")).toString().trimmed().toUpper() + QLatin1Char('\0')
                + record.value(QStringLiteral("value")).toString();
            const auto existing = indexes.constFind(key);
            if (existing != indexes.cend()) {
                const int index = existing.value();
                if (record.value(QStringLiteral("ttl")).toInt() > records.at(index).toObject().value(QStringLiteral("ttl")).toInt())
                    records.replace(index, record);
                continue;
            }
            indexes.insert(key, records.size());
            records.append(record);
        }
    };
    append(dns.value(QStringLiteral("inventory")).toObject().value(QStringLiteral("records")).toArray());
    append(dns.value(QStringLiteral("transfer")).toObject().value(QStringLiteral("records")).toArray());
    for (const QJsonValue &messageValue : dns.value(QStringLiteral("messages")).toArray()) {
        const QJsonObject message = messageValue.toObject();
        append(message.value(QStringLiteral("answer")).toArray());
        append(message.value(QStringLiteral("authority")).toArray());
        append(message.value(QStringLiteral("additional")).toArray());
    }
    for (const QJsonValue &remoteValue : dns.value(QStringLiteral("remote")).toArray())
        append(remoteValue.toObject().value(QStringLiteral("answers")).toArray());
    return records;
}

QString comparisonKey(const QJsonObject &value)
{
    return value.value(QStringLiteral("resolver")).toString() + QLatin1Char('\0')
        + value.value(QStringLiteral("name")).toString().trimmed().toLower() + QLatin1Char('\0')
        + value.value(QStringLiteral("type")).toString().trimmed().toUpper() + QLatin1Char('\0')
        + value.value(QStringLiteral("class")).toString().trimmed().toUpper();
}

QString comparisonDetails(const QJsonObject &message)
{
    QStringList values;
    for (const QString &value : {message.value(QStringLiteral("rcode")).toString(),
                                 message.value(QStringLiteral("transport")).toString().toUpper(),
                                 message.value(QStringLiteral("dnssec")).toString()}) {
        if (!value.isEmpty())
            values.append(value);
    }
    const double duration = message.value(QStringLiteral("duration_ns")).toDouble();
    if (duration > 0)
        values.append(QStringLiteral("%1 ms").arg(duration / 1000000.0, 0, 'f', 1));
    return values.join(QStringLiteral(" · "));
}

QString compactEventAction(QString action)
{
    action = action.trimmed().toLower();
    action.remove(QLatin1Char(' '));
    action.remove(QLatin1Char('-'));
    action.remove(QLatin1Char('_'));
    action.remove(QLatin1Char('.'));
    return action;
}

QString eventActionClass(const QString &action)
{
    const QString key = compactEventAction(action);
    if (key == QStringLiteral("registration") || key == QStringLiteral("registered")
        || key == QStringLiteral("creation") || key == QStringLiteral("created")
        || key == QStringLiteral("registrarregistration"))
        return QStringLiteral("registration");
    if (key == QStringLiteral("expiration") || key == QStringLiteral("expiry")
        || key == QStringLiteral("expires") || key == QStringLiteral("registryexpiration")
        || key == QStringLiteral("registryexpiry") || key == QStringLiteral("registrarexpiration"))
        return QStringLiteral("expiration");
    if (key == QStringLiteral("lastchanged") || key == QStringLiteral("lastupdate")
        || key == QStringLiteral("updated") || key == QStringLiteral("changed"))
        return QStringLiteral("lastchanged");
    if (key == QStringLiteral("lastupdateofrdapdatabase") || key == QStringLiteral("rdapdatabaseupdated"))
        return QStringLiteral("rdapupdated");
    return key;
}

QString canonicalEventAction(const QString &actionClass)
{
    if (actionClass == QStringLiteral("registration"))
        return QStringLiteral("registration");
    if (actionClass == QStringLiteral("expiration"))
        return QStringLiteral("expiration");
    if (actionClass == QStringLiteral("lastchanged"))
        return QStringLiteral("last changed");
    if (actionClass == QStringLiteral("rdapupdated"))
        return QStringLiteral("RDAP database updated");
    return {};
}

QString eventDateKey(const QString &date)
{
    const QString value = date.trimmed();
    QDateTime parsed = QDateTime::fromString(value, Qt::ISODateWithMs);
    if (!parsed.isValid())
        parsed = QDateTime::fromString(value, Qt::ISODate);
    if (parsed.isValid()) {
        int zoneStart = value.size();
        if (value.endsWith(QLatin1Char('Z'), Qt::CaseInsensitive))
            --zoneStart;
        else if (value.size() >= 6 && (value.at(value.size() - 6) == QLatin1Char('+') || value.at(value.size() - 6) == QLatin1Char('-')))
            zoneStart -= 6;
        QString fraction = QStringLiteral("0");
        const int dot = value.lastIndexOf(QLatin1Char('.'), zoneStart - 1);
        if (dot >= 0) {
            const QString candidate = value.mid(dot + 1, zoneStart - dot - 1);
            bool digitsOnly = !candidate.isEmpty();
            for (const QChar character : candidate)
                digitsOnly = digitsOnly && character.isDigit();
            if (digitsOnly) {
                fraction = candidate;
                while (fraction.endsWith(QLatin1Char('0')) && fraction.size() > 1)
                    fraction.chop(1);
            }
        }
        return QString::number(parsed.toSecsSinceEpoch()) + QLatin1Char('.') + fraction;
    }
    return value.toLower();
}

QList<QPair<QString, QString>> consolidatedEvents(const QJsonArray &values)
{
    QList<QPair<QString, QString>> unique;
    QHash<QString, int> semanticIndexes;
    for (const QJsonValue &value : values) {
        const QJsonObject event = value.toObject();
        QString action = event.value(QStringLiteral("action")).toString().trimmed();
        const QString date = event.value(QStringLiteral("date")).toString().trimmed();
        if (action.isEmpty() && date.isEmpty())
            continue;
        const QString actionClass = eventActionClass(action);
        const QString key = actionClass + QLatin1Char('\0') + eventDateKey(date);
        const auto existing = semanticIndexes.constFind(key);
        if (existing != semanticIndexes.cend()) {
            const QString canonical = canonicalEventAction(actionClass);
            if (!canonical.isEmpty())
                unique[existing.value()].first = canonical;
            continue;
        }
        semanticIndexes.insert(key, unique.size());
        unique.append(qMakePair(action, date));
    }

    QList<QPair<QString, QString>> rows;
    QStringList selectedDateKeys;
    QHash<QString, int> rowIndexes;
    for (const auto &event : unique) {
        const QString actionClass = eventActionClass(event.first);
        const QString canonical = canonicalEventAction(actionClass);
        const QString action = !canonical.isEmpty() ? canonical : (event.first.isEmpty() ? QStringLiteral("Event") : event.first);
        const QString date = event.second.isEmpty() ? QStringLiteral("unknown") : event.second;
        const QString actionKey = actionClass.isEmpty() ? compactEventAction(action) : actionClass;
        const auto existing = rowIndexes.constFind(actionKey);
        if (existing == rowIndexes.cend()) {
            rowIndexes.insert(actionKey, rows.size());
            rows.append(qMakePair(action, date));
            selectedDateKeys.append(eventDateKey(date));
            continue;
        }
        const int index = existing.value();
        const QString dateKey = eventDateKey(date);
        const bool preferEarlier = actionClass == QStringLiteral("registration");
        const bool replace = preferEarlier ? dateKey < selectedDateKeys[index] : dateKey > selectedDateKeys[index];
        if (replace) {
            rows[index].second = date;
            selectedDateKeys[index] = dateKey;
        }
    }
    return rows;
}

}

ResultWidget::ResultWidget(QWidget *parent)
    : QWidget(parent)
    , m_tabs(new QTabWidget(this))
    , m_overview(new QTreeWidget(this))
    , m_dns(new QTableWidget(this))
    , m_compare(new QTableWidget(this))
    , m_delegation(new QTableWidget(this))
    , m_services(new QTableWidget(this))
    , m_findings(new QTableWidget(this))
    , m_stack(new QTreeWidget(this))
    , m_stackPage(new QWidget(this))
    , m_stackSplitter(new QSplitter(Qt::Vertical, m_stackPage))
    , m_stackDetailTitle(new QLabel(m_stackPage))
    , m_stackDetailSummary(new QLabel(m_stackPage))
    , m_evidence(new QTableWidget(m_stackPage))
    , m_research(new QTreeWidget(this))
    , m_researchPage(new QWidget(this))
    , m_openResearch(new QPushButton(tr("Open selected"), m_researchPage))
    , m_copyResearch(new QPushButton(tr("Copy link"), m_researchPage))
    , m_related(new QTableWidget(this))
    , m_errors(new QTableWidget(this))
    , m_contacts(new QTableWidget(this))
    , m_rawSource(new QComboBox(this))
    , m_rawText(new QPlainTextEdit(this))
    , m_emptyLabel(new QLabel(tr("Enter a domain, IP address, ASN, or URL to begin."), this))
{
    m_emptyLabel->setAlignment(Qt::AlignCenter);
    m_emptyLabel->setWordWrap(true);

    m_overview->setObjectName(QStringLiteral("overviewTree"));
    m_stack->setObjectName(QStringLiteral("stackTree"));
    m_stackPage->setObjectName(QStringLiteral("stackPage"));
    m_evidence->setObjectName(QStringLiteral("stackEvidenceTable"));
    m_stackDetailTitle->setObjectName(QStringLiteral("stackDetailTitle"));
    m_stackDetailSummary->setObjectName(QStringLiteral("stackDetailSummary"));
    m_research->setObjectName(QStringLiteral("researchTree"));
    m_researchPage->setObjectName(QStringLiteral("researchPage"));
    m_openResearch->setObjectName(QStringLiteral("openResearchButton"));
    m_copyResearch->setObjectName(QStringLiteral("copyResearchButton"));
    m_related->setObjectName(QStringLiteral("relatedTable"));
    m_dns->setObjectName(QStringLiteral("dnsTable"));
    m_compare->setObjectName(QStringLiteral("compareTable"));
    m_delegation->setObjectName(QStringLiteral("delegationTable"));
    m_services->setObjectName(QStringLiteral("servicesTable"));
    m_findings->setObjectName(QStringLiteral("findingsTable"));
    m_errors->setObjectName(QStringLiteral("errorsTable"));
    m_contacts->setObjectName(QStringLiteral("contactsTable"));

    m_overview->setColumnCount(2);
    m_overview->setHeaderLabels({tr("Field"), tr("Value")});
    m_overview->setRootIsDecorated(true);
    m_overview->setAlternatingRowColors(true);
    AdaptiveItemView::configure(m_overview, QStringLiteral("result/layout-v1/overview"), {2, 5});

    configureTable(m_dns, {tr("Type"), tr("Name"), tr("TTL"), tr("Value")});
    AdaptiveItemView::configure(m_dns, QStringLiteral("result/layout-v1/dns"), {1, 3, 1, 6});

    configureTable(m_compare, {tr("Query"), tr("Resolver"), tr("Result"), tr("Details")});
    AdaptiveItemView::configure(m_compare, QStringLiteral("result/layout-v1/compare"), {3, 3, 2, 5});
    configureTable(m_delegation, {tr("Hop"), tr("Zone"), tr("Server"), tr("Result"), tr("Nameservers"), tr("Addresses")});
    AdaptiveItemView::configure(m_delegation, QStringLiteral("result/layout-v1/delegation"), {1, 2, 3, 2, 4, 4});
    configureTable(m_services, {tr("Category"), tr("Endpoint"), tr("Result"), tr("Details")});
    AdaptiveItemView::configure(m_services, QStringLiteral("result/layout-v1/services"), {2, 4, 2, 5});
    configureTable(m_findings, {tr("Result"), tr("Check"), tr("Summary")});
    AdaptiveItemView::configure(m_findings, QStringLiteral("result/layout-v1/findings"), {1, 3, 7});
    m_stack->setColumnCount(4);
    m_stack->setHeaderLabels({tr("Layer"), tr("Technology"), tr("Role"), tr("Confidence")});
    m_stack->setRootIsDecorated(true);
    m_stack->setAlternatingRowColors(true);
    AdaptiveItemView::configure(m_stack, QStringLiteral("result/layout-v1/stack"), {2, 4, 4, 2});

    configureTable(m_evidence, {tr("Source"), tr("Subject"), tr("Field"), tr("Value")});
    m_evidence->setEditTriggers(QAbstractItemView::NoEditTriggers);
    AdaptiveItemView::configure(m_evidence, QStringLiteral("result/layout-v1/stack-evidence"), {2, 3, 3, 7});

    m_research->setColumnCount(2);
    m_research->setHeaderLabels({tr("Service"), tr("What it adds")});
    m_research->setRootIsDecorated(true);
    m_research->setAlternatingRowColors(true);
    m_research->setSelectionMode(QAbstractItemView::SingleSelection);
    AdaptiveItemView::configure(m_research, QStringLiteral("result/layout-v1/research"), {3, 7});

    configureTable(m_related, {tr("Hostname"), tr("Observed IP"), tr("First seen"), tr("Last seen"), tr("Now"), tr("Current DNS"), tr("Source")});
    AdaptiveItemView::configure(m_related, QStringLiteral("result/layout-v1/related"), {4, 3, 3, 3, 2, 4, 2});
    m_related->setContextMenuPolicy(Qt::CustomContextMenu);
    configureTable(m_errors, {tr("Operation"), tr("Kind"), tr("Message")});
    AdaptiveItemView::configure(m_errors, QStringLiteral("result/layout-v1/errors"), {2, 2, 7});
    configureTable(m_contacts, {tr("Role"), tr("Name"), tr("Handle"), tr("Email"), tr("Phone"), tr("Organization")});
    AdaptiveItemView::configure(m_contacts, QStringLiteral("result/layout-v1/contacts"), {2, 3, 2, 4, 3, 4});

    QFont detailTitleFont = m_stackDetailTitle->font();
    detailTitleFont.setBold(true);
    m_stackDetailTitle->setFont(detailTitleFont);
    m_stackDetailTitle->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_stackDetailSummary->setWordWrap(true);
    m_stackDetailSummary->setTextInteractionFlags(Qt::TextSelectableByMouse);
    auto *detailPage = new QWidget(m_stackSplitter);
    auto *detailLayout = new QVBoxLayout(detailPage);
    detailLayout->setContentsMargins(8, 8, 8, 8);
    detailLayout->addWidget(m_stackDetailTitle);
    detailLayout->addWidget(m_stackDetailSummary);
    detailLayout->addWidget(m_evidence, 1);
    m_stackSplitter->addWidget(m_stack);
    m_stackSplitter->addWidget(detailPage);
    m_stackSplitter->setStretchFactor(0, 3);
    m_stackSplitter->setStretchFactor(1, 2);
    m_stackSplitter->setSizes({420, 240});
    auto *stackPageLayout = new QVBoxLayout(m_stackPage);
    stackPageLayout->setContentsMargins(0, 0, 0, 0);
    stackPageLayout->addWidget(m_stackSplitter);
    QSettings settings;
    m_stackSplitter->restoreState(settings.value(QStringLiteral("result/layout-v1/stack-splitter")).toByteArray());
    connect(m_stackSplitter, &QSplitter::splitterMoved, this, [this] {
        QSettings settings;
        settings.setValue(QStringLiteral("result/layout-v1/stack-splitter"), m_stackSplitter->saveState());
    });
    clearStackDetails();

    auto *researchLayout = new QVBoxLayout(m_researchPage);
    researchLayout->setContentsMargins(8, 8, 8, 8);
    auto *researchNote = new QLabel(tr("Whodis creates these links locally. A service receives the domain or IP only when you explicitly open its link. Some services may require an account."), m_researchPage);
    researchNote->setWordWrap(true);
    researchLayout->addWidget(researchNote);
    researchLayout->addWidget(m_research, 1);
    auto *researchActions = new QHBoxLayout;
    researchActions->addWidget(m_openResearch);
    researchActions->addWidget(m_copyResearch);
    researchActions->addStretch();
    researchLayout->addLayout(researchActions);
    updateResearchActions();

    m_rawPage = new QWidget(this);
    auto *rawLayout = new QVBoxLayout(m_rawPage);
    rawLayout->setContentsMargins(0, 0, 0, 0);
    rawLayout->addWidget(m_rawSource);
    rawLayout->addWidget(m_rawText);
    m_rawText->setReadOnly(true);
    m_rawText->setLineWrapMode(QPlainTextEdit::WidgetWidth);
    m_rawText->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    connect(m_rawSource, &QComboBox::currentIndexChanged, this, [this](int index) {
        m_rawText->setPlainText(m_rawSource->itemData(index, Qt::UserRole).toString());
    });

    m_tabs->addTab(m_overview, tr("Overview"));
    m_tabs->addTab(m_stackPage, tr("Stack"));
    m_tabs->addTab(m_researchPage, tr("Research"));
    m_tabs->addTab(m_related, tr("Related"));
    m_tabs->addTab(m_dns, tr("DNS"));
    m_tabs->addTab(m_compare, tr("Compare"));
    m_tabs->addTab(m_delegation, tr("Delegation"));
    m_tabs->addTab(m_services, tr("Services"));
    m_tabs->addTab(m_findings, tr("Findings"));
    m_tabs->addTab(m_errors, tr("Errors"));
    m_tabs->addTab(m_contacts, tr("Contacts"));
    m_tabs->addTab(m_rawPage, tr("Raw"));

    connect(m_stack, &QTreeWidget::currentItemChanged, this,
            [this](QTreeWidgetItem *current) { showStackDetails(current); });
    connect(m_research, &QTreeWidget::currentItemChanged, this, [this] { updateResearchActions(); });
    connect(m_research, &QTreeWidget::itemDoubleClicked, this, [this] { openSelectedResearchLink(); });
    connect(m_openResearch, &QPushButton::clicked, this, &ResultWidget::openSelectedResearchLink);
    connect(m_copyResearch, &QPushButton::clicked, this, [this] {
        const QTreeWidgetItem *item = m_research->currentItem();
        const QUrl url(item ? item->data(0, Qt::UserRole).toString() : QString());
        if (url.isValid() && url.scheme() == QStringLiteral("https") && url.userInfo().isEmpty())
            QGuiApplication::clipboard()->setText(url.toString());
    });
    connect(m_related, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &position) {
        const int row = m_related->rowAt(position.y());
        const QTableWidgetItem *hostname = row >= 0 ? m_related->item(row, 0) : nullptr;
        if (!hostname || hostname->text().isEmpty())
            return;
        QMenu menu(this);
        QAction *investigate = menu.addAction(tr("Investigate %1").arg(hostname->text()));
        if (menu.exec(m_related->viewport()->mapToGlobal(position)) == investigate)
            emit investigateRequested(hostname->text());
    });

    auto *stack = new QStackedLayout(this);
    stack->addWidget(m_emptyLabel);
    stack->addWidget(m_tabs);
    stack->setCurrentWidget(m_emptyLabel);
}

void ResultWidget::clearResult()
{
    m_item = {};
    m_overview->clear();
    m_dns->setRowCount(0);
    m_compare->setRowCount(0);
    m_delegation->setRowCount(0);
    m_services->setRowCount(0);
    m_findings->setRowCount(0);
    m_stack->clear();
    clearStackDetails();
    m_research->clear();
    updateResearchActions();
    m_related->setRowCount(0);
    m_errors->setRowCount(0);
    m_contacts->setRowCount(0);
    m_rawSource->clear();
    m_rawText->clear();
    if (auto *stack = qobject_cast<QStackedLayout *>(layout()))
        stack->setCurrentWidget(m_emptyLabel);
}

void ResultWidget::setItem(const QJsonObject &item)
{
    m_item = item;
    const QJsonObject result = item.value(QStringLiteral("result")).toObject();
    populateOverview(result);
    populateDNS(result);
    populateContacts(result);
    populateRaw(item.value(QStringLiteral("raw_sources")).toArray());
    m_tabs->setTabVisible(m_tabs->indexOf(m_overview), true);
    m_tabs->setTabVisible(m_tabs->indexOf(m_stackPage), false);
    m_tabs->setTabVisible(m_tabs->indexOf(m_researchPage), false);
    m_tabs->setTabVisible(m_tabs->indexOf(m_related), false);
    m_tabs->setTabVisible(m_tabs->indexOf(m_dns), m_dns->rowCount() > 0);
    m_tabs->setTabVisible(m_tabs->indexOf(m_compare), false);
    m_tabs->setTabVisible(m_tabs->indexOf(m_delegation), false);
    m_tabs->setTabVisible(m_tabs->indexOf(m_services), false);
    m_tabs->setTabVisible(m_tabs->indexOf(m_findings), false);
    m_tabs->setTabVisible(m_tabs->indexOf(m_errors), false);
    m_tabs->setTabVisible(m_tabs->indexOf(m_contacts), m_contacts->rowCount() > 0);
    m_tabs->setTabVisible(m_tabs->indexOf(m_rawPage), m_rawSource->count() > 0);
    m_tabs->setCurrentWidget(m_overview);
    refreshViews();
    if (auto *stack = qobject_cast<QStackedLayout *>(layout()))
        stack->setCurrentWidget(m_tabs);
}

void ResultWidget::setReportItem(const QJsonObject &item)
{
    clearResult();
    m_item = item;
    const QJsonObject report = item.value(QStringLiteral("report")).toObject();
    const QJsonObject registration = report.value(QStringLiteral("registration")).toObject();
    const QJsonObject investigation = report.value(QStringLiteral("investigation")).toObject();
    if (!registration.isEmpty()) {
        QJsonObject presentation = registration;
        presentation.insert(QStringLiteral("query"), report.value(QStringLiteral("subject")));
        presentation.insert(QStringLiteral("retrieved_at"), report.value(QStringLiteral("observed_at")));
        populateOverview(presentation);
        populateContacts(registration);
    } else {
        m_overview->clear();
        auto *operation = addGroup(m_overview, tr("Operation"));
        addValue(operation, tr("Target"), report.value(QStringLiteral("subject")).toObject().value(QStringLiteral("canonical")).toString());
        addValue(operation, tr("Action"), report.value(QStringLiteral("operation")).toString());
        addValue(operation, tr("Retrieved"), report.value(QStringLiteral("observed_at")).toString());
    }
    populateInvestigationOverview(investigation);
    populateReportDNS(report);
    populateCompare(report);
    populateDelegation(report);
    populateServices(report);
    populateFindings(report);
    populateInvestigation(report);
    populateResearch(report);
    populateErrors(report);
    populateRaw(item.value(QStringLiteral("raw_sources")).toArray());

    m_tabs->setTabVisible(m_tabs->indexOf(m_overview), true);
    m_tabs->setTabVisible(m_tabs->indexOf(m_stackPage), m_stack->topLevelItemCount() > 0);
    m_tabs->setTabVisible(m_tabs->indexOf(m_researchPage), m_research->topLevelItemCount() > 0);
    m_tabs->setTabVisible(m_tabs->indexOf(m_related), m_related->rowCount() > 0);
    m_tabs->setTabVisible(m_tabs->indexOf(m_dns), m_dns->rowCount() > 0);
    m_tabs->setTabVisible(m_tabs->indexOf(m_compare), m_compare->rowCount() > 0);
    m_tabs->setTabVisible(m_tabs->indexOf(m_delegation), m_delegation->rowCount() > 0);
    m_tabs->setTabVisible(m_tabs->indexOf(m_services), m_services->rowCount() > 0);
    m_tabs->setTabVisible(m_tabs->indexOf(m_findings), m_findings->rowCount() > 0);
    m_tabs->setTabVisible(m_tabs->indexOf(m_errors), m_errors->rowCount() > 0);
    m_tabs->setTabVisible(m_tabs->indexOf(m_contacts), m_contacts->rowCount() > 0);
    m_tabs->setTabVisible(m_tabs->indexOf(m_rawPage), m_rawSource->count() > 0);
    if (!investigation.isEmpty())
        m_tabs->setCurrentWidget(m_overview);
    else if (m_errors->rowCount() > 0)
        m_tabs->setCurrentWidget(m_errors);
    else if (m_findings->rowCount() > 0)
        m_tabs->setCurrentWidget(m_findings);
    else if (m_dns->rowCount() > 0 && registration.isEmpty())
        m_tabs->setCurrentWidget(m_dns);
    else
        m_tabs->setCurrentWidget(m_overview);
    refreshViews();
    if (auto *stack = qobject_cast<QStackedLayout *>(layout()))
        stack->setCurrentWidget(m_tabs);
}

void ResultWidget::showDNSTab()
{
    m_tabs->setCurrentWidget(m_dns);
}

QString ResultWidget::copyText() const
{
    if (m_tabs->currentWidget() == m_rawPage && !m_rawText->toPlainText().isEmpty())
        return m_rawText->toPlainText();
    const QJsonObject value = m_item.contains(QStringLiteral("report"))
        ? m_item.value(QStringLiteral("report")).toObject()
        : m_item.value(QStringLiteral("result")).toObject();
    return QString::fromUtf8(QJsonDocument(value).toJson(QJsonDocument::Indented));
}

QString ResultWidget::currentTarget() const
{
    return m_item.value(QStringLiteral("input")).toString();
}

QString ResultWidget::currentRawSource() const
{
    return m_rawSource->currentData(Qt::UserRole).toString();
}

bool ResultWidget::hasRawSource() const
{
    return m_rawSource->count() > 0 && !currentRawSource().isEmpty();
}

int ResultWidget::dnsRowCount() const
{
    return m_dns->rowCount();
}

int ResultWidget::relatedRowCount() const
{
    return m_related->rowCount();
}

void ResultWidget::setInvestigationLinkProviders(const QJsonArray &providers)
{
    m_researchPurposes.clear();
    for (const QJsonValue &value : providers) {
        const QJsonObject provider = value.toObject();
        const QString label = provider.value(QStringLiteral("label")).toString();
        if (!label.isEmpty())
            m_researchPurposes.insert(label, provider.value(QStringLiteral("purpose")).toString());
    }
}

void ResultWidget::populateOverview(const QJsonObject &result)
{
    m_overview->clear();
    const QJsonObject query = result.value(QStringLiteral("query")).toObject();
    const QJsonObject object = result.value(QStringLiteral("object")).toObject();
    const QJsonObject route = result.value(QStringLiteral("route")).toObject();

    auto *registration = addGroup(m_overview, tr("Registration"));
    addValue(registration, tr("Name"), object.value(QStringLiteral("name")).toString(query.value(QStringLiteral("canonical")).toString()));
    addValue(registration, tr("Unicode name"), object.value(QStringLiteral("unicode_name")).toString());
    addValue(registration, tr("Handle"), object.value(QStringLiteral("handle")).toString());
    addValue(registration, tr("Registrar"), object.value(QStringLiteral("registrar")).toString());
    addValue(registration, tr("Registry"), object.value(QStringLiteral("registry")).toString());
    addValue(registration, tr("Status"), joined(object.value(QStringLiteral("status"))));
    addValue(registration, QStringLiteral("DNSSEC"), object.value(QStringLiteral("dnssec")).toString());
    addValue(registration, tr("Network"), object.value(QStringLiteral("network_type")).toString());
    addValue(registration, QStringLiteral("CIDR"), joined(object.value(QStringLiteral("cidr"))));
    addValue(registration, QStringLiteral("ASN"), object.value(QStringLiteral("asn")).toString());
    addValue(registration, tr("ASN name"), object.value(QStringLiteral("asn_name")).toString());

    const QJsonArray events = object.value(QStringLiteral("events")).toArray();
    if (!events.isEmpty()) {
        auto *timeline = addGroup(m_overview, tr("Timeline"));
        for (const auto &event : consolidatedEvents(events))
            addValue(timeline, event.first, event.second);
        if (timeline->childCount() == 0)
            delete timeline;
    }

    const QJsonArray nameservers = object.value(QStringLiteral("nameservers")).toArray();
    if (!nameservers.isEmpty()) {
        auto *group = addGroup(m_overview, tr("Nameservers"));
        for (const QJsonValue &value : nameservers)
            new QTreeWidgetItem(group, {value.toString()});
    }

    auto *source = addGroup(m_overview, tr("Source"));
    addValue(source, tr("Protocol"), route.value(QStringLiteral("protocol")).toString().toUpper());
    addValue(source, tr("Authority"), route.value(QStringLiteral("endpoint")).toString());
    addValue(source, tr("Discovery"), route.value(QStringLiteral("discovery_source")).toString());
    addValue(source, tr("Reason"), route.value(QStringLiteral("reason")).toString());
    addValue(source, tr("Retrieved"), result.value(QStringLiteral("retrieved_at")).toString());

    const QJsonArray notices = object.value(QStringLiteral("notices")).toArray();
    if (!notices.isEmpty()) {
        auto *noticeGroup = addGroup(m_overview, tr("Notices (%1)").arg(notices.size()));
        noticeGroup->setExpanded(false);
        for (const QJsonValue &value : notices) {
            const QJsonObject notice = value.toObject();
            auto *entry = new QTreeWidgetItem(noticeGroup, {notice.value(QStringLiteral("title")).toString()});
            addValue(entry, tr("Description"), joined(notice.value(QStringLiteral("description"))));
            addValue(entry, tr("Links"), joined(notice.value(QStringLiteral("links"))));
        }
    }
}

void ResultWidget::populateInvestigationOverview(const QJsonObject &investigation)
{
    if (investigation.isEmpty())
        return;

    struct CategorySummary {
        QString label;
        QStringList keys;
    };
    const QList<CategorySummary> categories{
        {tr("Web technology"), {QStringLiteral("web_application"), QStringLiteral("framework")}},
        {tr("Server / edge"), {QStringLiteral("web_server"), QStringLiteral("edge")}},
        {tr("Hosting"), {QStringLiteral("hosting")}},
        {tr("Network owner"), {QStringLiteral("network")}},
        {tr("DNS provider"), {QStringLiteral("dns")}},
        {tr("Mail"), {QStringLiteral("mail")}},
        {tr("Analytics / security"), {QStringLiteral("analytics"), QStringLiteral("security")}},
        {tr("Other"), {QStringLiteral("other")}},
    };
    QList<QStringList> values(categories.size());
    for (const QJsonValue &value : investigation.value(QStringLiteral("components")).toArray()) {
        const QJsonObject component = value.toObject();
        const QString confidence = component.value(QStringLiteral("confidence")).toString().trimmed().toLower();
        if (confidence != QStringLiteral("high") && confidence != QStringLiteral("medium"))
            continue;
        const QString name = component.value(QStringLiteral("name")).toString().trimmed();
        if (name.isEmpty())
            continue;
        const QString category = component.value(QStringLiteral("category")).toString().trimmed().toLower();
        int categoryIndex = categories.size() - 1;
        for (int index = 0; index < categories.size(); ++index) {
            if (categories.at(index).keys.contains(category)) {
                categoryIndex = index;
                break;
            }
        }
        bool duplicate = false;
        for (const QString &existing : values.at(categoryIndex)) {
            if (existing.compare(name, Qt::CaseInsensitive) == 0) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate)
            values[categoryIndex].append(name);
    }

    auto *group = addGroup(m_overview, tr("Technology & infrastructure"));
    for (int index = 0; index < categories.size(); ++index) {
        const QStringList names = values.at(index);
        if (names.isEmpty())
            continue;
        QString display = names.mid(0, 3).join(QStringLiteral(", "));
        if (names.size() > 3)
            display += tr(" +%1").arg(names.size() - 3);
        auto *row = new QTreeWidgetItem(group, {categories.at(index).label, display});
        row->setToolTip(1, names.join(QLatin1Char('\n')));
    }
    if (group->childCount() == 0)
        addValue(group, tr("Profile"), investigation.value(QStringLiteral("summary")).toString());
    if (group->childCount() == 0) {
        delete group;
        return;
    }

    const int currentIndex = m_overview->indexOfTopLevelItem(group);
    QTreeWidgetItem *detached = m_overview->takeTopLevelItem(currentIndex);
    m_overview->insertTopLevelItem(qMin(1, m_overview->topLevelItemCount()), detached);
}

void ResultWidget::populateDNS(const QJsonObject &result)
{
    m_dns->setSortingEnabled(false);
    m_dns->setRowCount(0);
    const QJsonArray rawRecords = result.value(QStringLiteral("dns")).toObject().value(QStringLiteral("records")).toArray();
    const QJsonObject inventory{{QStringLiteral("records"), rawRecords}};
    const QJsonArray records = operationRecords(QJsonObject{{QStringLiteral("inventory"), inventory}});
    m_dns->setRowCount(records.size());
    for (int row = 0; row < records.size(); ++row) {
        const QJsonObject record = records.at(row).toObject();
        m_dns->setItem(row, 0, new QTableWidgetItem(record.value(QStringLiteral("type")).toString()));
        m_dns->setItem(row, 1, new QTableWidgetItem(record.value(QStringLiteral("name")).toString()));
        auto *ttl = new QTableWidgetItem;
        ttl->setData(Qt::DisplayRole, record.value(QStringLiteral("ttl")).toInt());
        m_dns->setItem(row, 2, ttl);
        m_dns->setItem(row, 3, new QTableWidgetItem(record.value(QStringLiteral("value")).toString()));
    }
    m_dns->setSortingEnabled(true);
}

void ResultWidget::populateReportDNS(const QJsonObject &report)
{
    m_dns->setSortingEnabled(false);
    m_dns->setRowCount(0);
    const QJsonArray records = operationRecords(reportDNS(report));
    m_dns->setRowCount(records.size());
    for (int row = 0; row < records.size(); ++row) {
        const QJsonObject record = records.at(row).toObject();
        m_dns->setItem(row, 0, new QTableWidgetItem(record.value(QStringLiteral("type")).toString()));
        m_dns->setItem(row, 1, new QTableWidgetItem(record.value(QStringLiteral("name")).toString()));
        auto *ttl = new QTableWidgetItem;
        ttl->setData(Qt::DisplayRole, record.value(QStringLiteral("ttl")).toInt());
        m_dns->setItem(row, 2, ttl);
        m_dns->setItem(row, 3, new QTableWidgetItem(record.value(QStringLiteral("value")).toString()));
    }
    m_dns->setSortingEnabled(true);
}

void ResultWidget::populateCompare(const QJsonObject &report)
{
    m_compare->setSortingEnabled(false);
    m_compare->setRowCount(0);
    const QJsonObject dns = reportDNS(report);
    const QJsonArray differences = dns.value(QStringLiteral("differences")).toArray();
    if (dns.value(QStringLiteral("mode")).toString() != QStringLiteral("compare") && differences.isEmpty()) {
        m_compare->setSortingEnabled(true);
        return;
    }

    QHash<QString, QJsonObject> differencesByQuery;
    QHash<QString, QJsonObject> legacyDifferencesByResolver;
    for (const QJsonValue &value : differences) {
        const QJsonObject difference = value.toObject();
        if (difference.value(QStringLiteral("name")).toString().isEmpty())
            legacyDifferencesByResolver.insert(difference.value(QStringLiteral("resolver")).toString(), difference);
        else
            differencesByQuery.insert(comparisonKey(difference), difference);
    }

    const auto addRow = [this](const QString &query, const QString &resolver, const QString &result, const QString &details) {
        const int row = m_compare->rowCount();
        m_compare->insertRow(row);
        m_compare->setItem(row, 0, new QTableWidgetItem(query));
        m_compare->setItem(row, 1, new QTableWidgetItem(resolver));
        m_compare->setItem(row, 2, new QTableWidgetItem(result));
        m_compare->setItem(row, 3, new QTableWidgetItem(details));
    };

    for (const QJsonValue &value : dns.value(QStringLiteral("messages")).toArray()) {
        const QJsonObject message = value.toObject();
        const QString resolver = message.value(QStringLiteral("resolver")).toString();
        const QString query = (message.value(QStringLiteral("name")).toString() + QLatin1Char(' ')
                               + message.value(QStringLiteral("type")).toString()).trimmed();
        QJsonObject difference = differencesByQuery.take(comparisonKey(message));
        if (difference.isEmpty())
            difference = legacyDifferencesByResolver.take(resolver);
        const QString error = message.value(QStringLiteral("error")).toString();
        if (!error.isEmpty()) {
            addRow(query, resolver, tr("Failed"), error);
        } else if (!difference.isEmpty()) {
            QStringList details;
            const QString missing = joined(difference.value(QStringLiteral("missing")));
            const QString extra = joined(difference.value(QStringLiteral("extra")));
            if (!missing.isEmpty())
                details.append(tr("Missing: %1").arg(missing));
            if (!extra.isEmpty())
                details.append(tr("Extra: %1").arg(extra));
            addRow(query, resolver, tr("Different"), details.join(QStringLiteral(" · ")));
        } else {
            addRow(query, resolver, tr("Agrees"), comparisonDetails(message));
        }
    }

    const auto addUnmatchedDifference = [&addRow](const QJsonObject &difference) {
        const QString query = (difference.value(QStringLiteral("name")).toString() + QLatin1Char(' ')
                               + difference.value(QStringLiteral("type")).toString()).trimmed();
        QStringList details;
        const QString missing = joined(difference.value(QStringLiteral("missing")));
        const QString extra = joined(difference.value(QStringLiteral("extra")));
        if (!missing.isEmpty())
            details.append(QObject::tr("Missing: %1").arg(missing));
        if (!extra.isEmpty())
            details.append(QObject::tr("Extra: %1").arg(extra));
        addRow(query, difference.value(QStringLiteral("resolver")).toString(), QObject::tr("Different"), details.join(QStringLiteral(" · ")));
    };
    for (const QJsonObject &difference : differencesByQuery)
        addUnmatchedDifference(difference);
    for (const QJsonObject &difference : legacyDifferencesByResolver)
        addUnmatchedDifference(difference);
    if (m_compare->rowCount() == 0)
        addRow({}, tr("All resolvers"), tr("Agrees"), tr("Resolvers agree after TTL and answer-order normalization."));
    m_compare->setSortingEnabled(true);
}

void ResultWidget::populateDelegation(const QJsonObject &report)
{
    m_delegation->setSortingEnabled(false);
    QJsonObject delegation = reportDNS(report);
    const QJsonObject diagnosisDelegation = report.value(QStringLiteral("diagnosis")).toObject().value(QStringLiteral("delegation")).toObject();
    if (!diagnosisDelegation.isEmpty())
        delegation = diagnosisDelegation;
    const QJsonArray trace = delegation.value(QStringLiteral("trace")).toArray();
    m_delegation->setRowCount(trace.size());
    for (int row = 0; row < trace.size(); ++row) {
        const QJsonObject hop = trace.at(row).toObject();
        m_delegation->setItem(row, 0, new QTableWidgetItem(QString::number(row + 1)));
        m_delegation->setItem(row, 1, new QTableWidgetItem(hop.value(QStringLiteral("zone")).toString()));
        m_delegation->setItem(row, 2, new QTableWidgetItem(hop.value(QStringLiteral("server")).toString()));
        m_delegation->setItem(row, 3, new QTableWidgetItem(hop.value(QStringLiteral("error")).toString(hop.value(QStringLiteral("rcode")).toString())));
        m_delegation->setItem(row, 4, new QTableWidgetItem(joined(hop.value(QStringLiteral("nameservers")))));
        m_delegation->setItem(row, 5, new QTableWidgetItem(joined(hop.value(QStringLiteral("addresses")))));
    }
    m_delegation->setSortingEnabled(true);
}

void ResultWidget::populateServices(const QJsonObject &report)
{
    m_services->setSortingEnabled(false);
    m_services->setRowCount(0);
    const QJsonObject diagnosis = report.value(QStringLiteral("diagnosis")).toObject();
    const auto addRow = [this](const QString &category, const QString &endpoint, const QString &result, const QString &details) {
        const int row = m_services->rowCount();
        m_services->insertRow(row);
        m_services->setItem(row, 0, new QTableWidgetItem(category));
        m_services->setItem(row, 1, new QTableWidgetItem(endpoint));
        m_services->setItem(row, 2, new QTableWidgetItem(result));
        m_services->setItem(row, 3, new QTableWidgetItem(details));
    };
    for (const QJsonValue &value : reportDNS(report).value(QStringLiteral("remote")).toArray()) {
        const QJsonObject probe = value.toObject();
        addRow(tr("Globalping"), probe.value(QStringLiteral("location")).toString(),
               probe.value(QStringLiteral("error")).toString(probe.value(QStringLiteral("status")).toString()),
               probe.value(QStringLiteral("resolver")).toString());
    }
    for (const QJsonValue &value : diagnosis.value(QStringLiteral("reachability")).toArray()) {
        const QJsonObject probe = value.toObject();
        addRow(tr("Network"), probe.value(QStringLiteral("address")).toString(),
               probe.value(QStringLiteral("reachable")).toBool() ? tr("Reachable") : tr("Failed"),
               probe.value(QStringLiteral("error")).toString());
    }
    for (const QJsonValue &value : diagnosis.value(QStringLiteral("http")).toArray()) {
        const QJsonObject probe = value.toObject();
        addRow(QStringLiteral("HTTP"), probe.value(QStringLiteral("url")).toString(),
               probe.value(QStringLiteral("error")).toString(QString::number(probe.value(QStringLiteral("status")).toInt())),
               probe.value(QStringLiteral("final_url")).toString());
    }
    for (const QJsonValue &value : diagnosis.value(QStringLiteral("tls")).toArray()) {
        const QJsonObject probe = value.toObject();
        addRow(QStringLiteral("TLS"), probe.value(QStringLiteral("server_name")).toString(),
               probe.value(QStringLiteral("verified")).toBool() ? tr("Verified") : tr("Failed"),
               probe.value(QStringLiteral("version")).toString() + QStringLiteral(" ") + probe.value(QStringLiteral("alpn")).toString());
    }
    for (const QJsonValue &value : diagnosis.value(QStringLiteral("mail")).toArray()) {
        const QJsonObject probe = value.toObject();
        addRow(QStringLiteral("SMTP"), probe.value(QStringLiteral("host")).toString(),
               probe.value(QStringLiteral("reachable")).toBool() ? tr("Reachable") : tr("Failed"),
               probe.value(QStringLiteral("starttls")).toBool() ? QStringLiteral("STARTTLS") : probe.value(QStringLiteral("error")).toString());
    }
    for (const QJsonValue &value : diagnosis.value(QStringLiteral("services")).toArray()) {
        const QJsonObject probe = value.toObject();
        addRow(probe.value(QStringLiteral("source")).toString(),
               probe.value(QStringLiteral("target")).toString() + QStringLiteral(":") + QString::number(probe.value(QStringLiteral("port")).toInt()),
               probe.value(QStringLiteral("reachable")).toBool() ? tr("Reachable") : tr("Failed"),
               probe.value(QStringLiteral("name")).toString());
    }
    for (const QJsonValue &value : diagnosis.value(QStringLiteral("path")).toArray()) {
        const QJsonObject hop = value.toObject();
        addRow(tr("Path hop %1").arg(hop.value(QStringLiteral("hop")).toInt()),
               hop.value(QStringLiteral("address")).toString(),
               hop.value(QStringLiteral("reached")).toBool() ? tr("Destination") : tr("Transit"),
               hop.value(QStringLiteral("error")).toString());
    }
    m_services->setSortingEnabled(true);
}

void ResultWidget::populateInvestigation(const QJsonObject &report)
{
    m_stack->clear();
    clearStackDetails();
    m_related->setSortingEnabled(false);
    m_related->setRowCount(0);
    const QJsonObject investigation = report.value(QStringLiteral("investigation")).toObject();
    if (investigation.isEmpty()) {
        m_related->setSortingEnabled(true);
        return;
    }

    QHash<QString, QTreeWidgetItem *> categories;
    QTreeWidgetItem *firstLeaf = nullptr;
    for (const QJsonValue &value : investigation.value(QStringLiteral("components")).toArray()) {
        const QJsonObject component = value.toObject();
        const QString categoryKey = component.value(QStringLiteral("category")).toString();
        QTreeWidgetItem *group = categories.value(categoryKey);
        if (!group) {
            QString label = categoryKey;
            label.replace(QLatin1Char('_'), QLatin1Char(' '));
            if (!label.isEmpty())
                label[0] = label.at(0).toUpper();
            group = addStackGroup(m_stack, label);
            categories.insert(categoryKey, group);
        }
        auto *technology = new QTreeWidgetItem(group, {QString(), component.value(QStringLiteral("name")).toString(),
                                                       component.value(QStringLiteral("role")).toString(),
                                                       component.value(QStringLiteral("confidence")).toString().toUpper()});
        setStackPayload(technology, QStringLiteral("component"), component);
        if (!firstLeaf)
            firstLeaf = technology;
    }

    const QJsonArray networks = investigation.value(QStringLiteral("networks")).toArray();
    if (!networks.isEmpty()) {
        auto *group = addStackGroup(m_stack, tr("Network attribution"));
        for (const QJsonValue &value : networks) {
            const QJsonObject network = value.toObject();
            auto *networkItem = new QTreeWidgetItem(group, {network.value(QStringLiteral("address")).toString(), network.value(QStringLiteral("provider")).toString(),
                                                     tr("Network owner"), QStringLiteral("HIGH")});
            setStackPayload(networkItem, QStringLiteral("network"), network);
            if (!firstLeaf)
                firstLeaf = networkItem;
        }
    }

    const QJsonArray warnings = investigation.value(QStringLiteral("warnings")).toArray();
    if (!warnings.isEmpty()) {
        auto *group = addStackGroup(m_stack, tr("Notes"));
        group->setExpanded(false);
        for (const QJsonValue &value : warnings) {
            auto *item = new QTreeWidgetItem(group, {tr("Note"), value.toString(), QString(), QString()});
            setStackPayload(item, QStringLiteral("warning"), {{QStringLiteral("message"), value.toString()}});
            if (!firstLeaf)
                firstLeaf = item;
        }
    }

    const QJsonArray related = investigation.value(QStringLiteral("related")).toArray();
    m_related->setRowCount(related.size());
    for (int row = 0; row < related.size(); ++row) {
        const QJsonObject observation = related.at(row).toObject();
        m_related->setItem(row, 0, new QTableWidgetItem(observation.value(QStringLiteral("hostname")).toString()));
        m_related->setItem(row, 1, new QTableWidgetItem(observation.value(QStringLiteral("address")).toString()));
        m_related->setItem(row, 2, new QTableWidgetItem(observation.value(QStringLiteral("first_seen")).toString()));
        m_related->setItem(row, 3, new QTableWidgetItem(observation.value(QStringLiteral("last_seen")).toString()));
        m_related->setItem(row, 4, new QTableWidgetItem(observation.value(QStringLiteral("current")).toString().toUpper()));
        m_related->setItem(row, 5, new QTableWidgetItem(joined(observation.value(QStringLiteral("current_values")))));
        m_related->setItem(row, 6, new QTableWidgetItem(observation.value(QStringLiteral("provider")).toString()));
    }
    const int total = investigation.value(QStringLiteral("related_total")).toInt(related.size());
    m_tabs->setTabToolTip(m_tabs->indexOf(m_related), total > related.size()
                             ? tr("Showing %1 of %2 passive observations. These are not ownership claims.").arg(related.size()).arg(total)
                             : tr("Passive observations are historical provider data, not ownership claims."));
    m_related->setSortingEnabled(true);
    if (firstLeaf)
        m_stack->setCurrentItem(firstLeaf);
    AdaptiveItemView::refresh(m_stack);
    AdaptiveItemView::refresh(m_related);
}

void ResultWidget::clearStackDetails()
{
    m_stackDetailTitle->setText(tr("Details"));
    m_stackDetailSummary->setText(tr("Select a technology, network, link, or note to see its details."));
    m_evidence->setSortingEnabled(false);
    m_evidence->setRowCount(0);
    m_evidence->setSortingEnabled(true);
    m_evidence->setVisible(false);
}

void ResultWidget::showStackDetails(QTreeWidgetItem *item)
{
    const QString kind = item ? item->data(0, StackKindRole).toString() : QString();
    const QJsonObject payload = stackPayload(item);
    if (kind.isEmpty() || payload.isEmpty()) {
        clearStackDetails();
        return;
    }

    clearStackDetails();
    m_evidence->setSortingEnabled(false);
    const auto addEvidence = [this](const QString &source, const QString &subject,
                                    const QString &field, const QString &value) {
        if (value.trimmed().isEmpty())
            return;
        const int row = m_evidence->rowCount();
        m_evidence->insertRow(row);
        m_evidence->setItem(row, 0, new QTableWidgetItem(source));
        m_evidence->setItem(row, 1, new QTableWidgetItem(subject));
        m_evidence->setItem(row, 2, new QTableWidgetItem(field));
        m_evidence->setItem(row, 3, new QTableWidgetItem(value));
    };
    if (kind == QStringLiteral("component")) {
        m_stackDetailTitle->setText(payload.value(QStringLiteral("name")).toString());
        QString summary = payload.value(QStringLiteral("summary")).toString();
        if (summary.isEmpty())
            summary = payload.value(QStringLiteral("role")).toString();
        m_stackDetailSummary->setText(summary);
        for (const QJsonValue &value : payload.value(QStringLiteral("evidence")).toArray()) {
            const QJsonObject evidence = value.toObject();
            addEvidence(evidence.value(QStringLiteral("source")).toString(),
                        evidence.value(QStringLiteral("subject")).toString(),
                        evidence.value(QStringLiteral("field")).toString(),
                        evidence.value(QStringLiteral("value")).toString());
        }
    } else if (kind == QStringLiteral("network")) {
        const QString address = payload.value(QStringLiteral("address")).toString();
        const QString provider = payload.value(QStringLiteral("provider")).toString();
        m_stackDetailTitle->setText(provider.isEmpty() ? address : address + QStringLiteral(" — ") + provider);
        const QString owner = payload.value(QStringLiteral("operator")).toString(payload.value(QStringLiteral("network_name")).toString());
        m_stackDetailSummary->setText(owner.isEmpty() ? tr("Public network attribution") : tr("Registered operator: %1").arg(owner));
        addEvidence(payload.value(QStringLiteral("source")).toString(), address, tr("Provider"), provider);
        addEvidence(payload.value(QStringLiteral("source")).toString(), address, tr("Operator"), owner);
        addEvidence(payload.value(QStringLiteral("source")).toString(), address, QStringLiteral("PTR"), joined(payload.value(QStringLiteral("ptr"))));
        addEvidence(payload.value(QStringLiteral("source")).toString(), address, QStringLiteral("CIDR"), joined(payload.value(QStringLiteral("cidr"))));
        addEvidence(payload.value(QStringLiteral("source")).toString(), address, tr("Country"), payload.value(QStringLiteral("country")).toString());
    } else if (kind == QStringLiteral("warning")) {
        m_stackDetailTitle->setText(tr("Note"));
        m_stackDetailSummary->setText(payload.value(QStringLiteral("message")).toString());
    }

    m_evidence->setSortingEnabled(true);
    m_evidence->setVisible(m_evidence->rowCount() > 0);
    AdaptiveItemView::refresh(m_evidence);
}

void ResultWidget::populateResearch(const QJsonObject &report)
{
    m_research->clear();
    const QJsonObject investigation = report.value(QStringLiteral("investigation")).toObject();
    if (investigation.isEmpty()) {
        updateResearchActions();
        return;
    }

    QHash<QString, QTreeWidgetItem *> groups;
    const auto appendLinks = [this, &groups](const QJsonArray &links) {
        for (const QJsonValue &value : links) {
            const QJsonObject link = value.toObject();
            const QUrl url(link.value(QStringLiteral("url")).toString());
            if (!url.isValid() || url.scheme() != QStringLiteral("https") || url.host().isEmpty() || !url.userInfo().isEmpty())
                continue;
            const QString targetType = link.value(QStringLiteral("type")).toString();
            const QString target = link.value(QStringLiteral("value")).toString();
            const QString key = targetType + QLatin1Char('\0') + target;
            QTreeWidgetItem *group = groups.value(key);
            if (!group) {
                QString typeLabel = tr("Domain");
                if (targetType == QStringLiteral("ip"))
                    typeLabel = target.contains(QLatin1Char(':')) ? QStringLiteral("IPv6") : QStringLiteral("IPv4");
                group = addStackGroup(m_research, typeLabel + QStringLiteral(" — ") + target);
                groups.insert(key, group);
            }
            const QString label = link.value(QStringLiteral("label")).toString(tr("Research service"));
            QString purpose = m_researchPurposes.value(label);
            if (purpose.isEmpty())
                purpose = tr("Manual investigation pivot");
            auto *item = new QTreeWidgetItem(group, {label, purpose});
            item->setData(0, Qt::UserRole, url.toString());
            item->setToolTip(0, url.toString());
            item->setToolTip(1, url.toString());
        }
    };

    appendLinks(investigation.value(QStringLiteral("links")).toArray());
    for (const QJsonValue &value : investigation.value(QStringLiteral("networks")).toArray())
        appendLinks(value.toObject().value(QStringLiteral("links")).toArray());
    updateResearchActions();
    AdaptiveItemView::refresh(m_research);
}

void ResultWidget::updateResearchActions()
{
    const QTreeWidgetItem *item = m_research->currentItem();
    const QUrl url(item ? item->data(0, Qt::UserRole).toString() : QString());
    const bool valid = url.isValid() && url.scheme() == QStringLiteral("https") && !url.host().isEmpty() && url.userInfo().isEmpty();
    m_openResearch->setEnabled(valid);
    m_copyResearch->setEnabled(valid);
}

void ResultWidget::openSelectedResearchLink()
{
    const QTreeWidgetItem *item = m_research->currentItem();
    const QUrl url(item ? item->data(0, Qt::UserRole).toString() : QString());
    if (url.isValid() && url.scheme() == QStringLiteral("https") && !url.host().isEmpty() && url.userInfo().isEmpty())
        QDesktopServices::openUrl(url);
}

void ResultWidget::refreshViews()
{
    AdaptiveItemView::refresh(m_overview);
    AdaptiveItemView::refresh(m_stack);
    AdaptiveItemView::refresh(m_research);
    for (QTableWidget *table : {m_dns, m_compare, m_delegation, m_services, m_findings,
                                m_evidence, m_related, m_errors, m_contacts})
        AdaptiveItemView::refresh(table);
}

void ResultWidget::populateFindings(const QJsonObject &report)
{
    m_findings->setSortingEnabled(false);
    QJsonArray findings = report.value(QStringLiteral("findings")).toArray();
    for (const QJsonValue &finding : report.value(QStringLiteral("diagnosis")).toObject().value(QStringLiteral("findings")).toArray()) {
        if (!findings.contains(finding))
            findings.append(finding);
    }
    m_findings->setRowCount(findings.size());
    for (int row = 0; row < findings.size(); ++row) {
        const QJsonObject finding = findings.at(row).toObject();
        m_findings->setItem(row, 0, new QTableWidgetItem(finding.value(QStringLiteral("severity")).toString().toUpper()));
        m_findings->setItem(row, 1, new QTableWidgetItem(finding.value(QStringLiteral("title")).toString()));
        m_findings->setItem(row, 2, new QTableWidgetItem(finding.value(QStringLiteral("summary")).toString()));
    }
    m_findings->setSortingEnabled(true);
}

void ResultWidget::populateErrors(const QJsonObject &report)
{
    m_errors->setSortingEnabled(false);
    const QJsonArray errors = report.value(QStringLiteral("errors")).toArray();
    m_errors->setRowCount(errors.size());
    for (int row = 0; row < errors.size(); ++row) {
        const QJsonObject error = errors.at(row).toObject();
        m_errors->setItem(row, 0, new QTableWidgetItem(error.value(QStringLiteral("operation")).toString()));
        m_errors->setItem(row, 1, new QTableWidgetItem(error.value(QStringLiteral("kind")).toString()));
        m_errors->setItem(row, 2, new QTableWidgetItem(error.value(QStringLiteral("message")).toString()));
    }
    m_errors->setSortingEnabled(true);
}

void ResultWidget::populateContacts(const QJsonObject &result)
{
    m_contacts->setSortingEnabled(false);
    m_contacts->setRowCount(0);
    const QJsonArray entities = result.value(QStringLiteral("object")).toObject().value(QStringLiteral("entities")).toArray();
    m_contacts->setRowCount(entities.size());
    for (int row = 0; row < entities.size(); ++row) {
        const QJsonObject entity = entities.at(row).toObject();
        m_contacts->setItem(row, 0, new QTableWidgetItem(joined(entity.value(QStringLiteral("roles")))));
        m_contacts->setItem(row, 1, new QTableWidgetItem(entity.value(QStringLiteral("name")).toString()));
        m_contacts->setItem(row, 2, new QTableWidgetItem(entity.value(QStringLiteral("handle")).toString()));
        m_contacts->setItem(row, 3, new QTableWidgetItem(entity.value(QStringLiteral("email")).toString()));
        m_contacts->setItem(row, 4, new QTableWidgetItem(entity.value(QStringLiteral("phone")).toString()));
        m_contacts->setItem(row, 5, new QTableWidgetItem(entity.value(QStringLiteral("organization")).toString()));
    }
    m_contacts->setSortingEnabled(true);
}

void ResultWidget::populateRaw(const QJsonArray &sources)
{
    m_rawSource->clear();
    for (const QJsonValue &value : sources) {
        const QJsonObject source = value.toObject();
        const QString label = source.value(QStringLiteral("protocol")).toString().toUpper()
            + QStringLiteral(" — ") + source.value(QStringLiteral("endpoint")).toString();
        m_rawSource->addItem(label, source.value(QStringLiteral("content")).toString());
    }
    m_rawText->setPlainText(m_rawSource->count() > 0 ? m_rawSource->itemData(0).toString() : QString());
}
