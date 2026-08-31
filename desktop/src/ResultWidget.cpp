#include "ResultWidget.h"

#include "AdaptiveItemView.h"
#include "ExternalLinks.h"

#include <QAbstractItemView>
#include <QApplication>
#include <QComboBox>
#include <QClipboard>
#include <QDateTime>
#include <QGuiApplication>
#include <QHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonValue>
#include <QHBoxLayout>
#include <QItemSelectionModel>
#include <QLabel>
#include <QMenu>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSettings>
#include <QSplitter>
#include <QStackedLayout>
#include <QTableWidget>
#include <QTabWidget>
#include <QTextCursor>
#include <QTreeWidget>
#include <QUrl>
#include <QVBoxLayout>

#include <algorithm>

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
    table->setSelectionBehavior(QAbstractItemView::SelectItems);
    table->setSelectionMode(QAbstractItemView::ExtendedSelection);
    table->setSortingEnabled(true);
    table->setAlternatingRowColors(true);
}

QList<int> modelIndexPath(QModelIndex index)
{
    QList<int> path;
    while (index.isValid()) {
        path.prepend(index.row());
        index = index.parent();
    }
    return path;
}

struct SelectedCell {
    QModelIndex index;
    QList<int> path;
};

QString selectedItemViewText(const QAbstractItemView *view)
{
    if (!view || !view->selectionModel())
        return {};
    QList<SelectedCell> cells;
    for (const QModelIndex &index : view->selectionModel()->selectedIndexes())
        cells.append({index, modelIndexPath(index)});
    std::sort(cells.begin(), cells.end(), [](const SelectedCell &left, const SelectedCell &right) {
        if (left.path != right.path) {
            return std::lexicographical_compare(left.path.cbegin(), left.path.cend(),
                                                right.path.cbegin(), right.path.cend());
        }
        return left.index.column() < right.index.column();
    });

    QStringList lines;
    QStringList fields;
    QList<int> rowPath;
    for (const SelectedCell &cell : cells) {
        if (!fields.isEmpty() && cell.path != rowPath) {
            lines.append(fields.join(QLatin1Char('\t')));
            fields.clear();
        }
        rowPath = cell.path;
        QString field = cell.index.data(Qt::DisplayRole).toString();
        if (cells.size() > 1) {
            field.replace(QLatin1Char('\t'), QLatin1Char(' '));
            field.replace(QLatin1Char('\r'), QLatin1Char(' '));
            field.replace(QLatin1Char('\n'), QLatin1Char(' '));
        }
        fields.append(field);
    }
    if (!fields.isEmpty())
        lines.append(fields.join(QLatin1Char('\t')));
    return lines.join(QLatin1Char('\n'));
}

QUrl researchUrl(const QModelIndex &index)
{
    if (!index.isValid())
        return {};
    const QUrl url(index.siblingAtColumn(0).data(Qt::UserRole).toString());
    if (!url.isValid() || url.scheme() != QStringLiteral("https") || url.host().isEmpty() || !url.userInfo().isEmpty())
        return {};
    return url;
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

bool jsonArrayContains(const QJsonArray &values, const QString &candidate)
{
    for (const QJsonValue &value : values) {
        if (value.toString().compare(candidate, Qt::CaseInsensitive) == 0)
            return true;
    }
    return false;
}

QString technologyGroupKey(const QJsonObject &component)
{
    const QJsonArray traits = component.value(QStringLiteral("traits")).toArray();
    if (jsonArrayContains(traits, QStringLiteral("WordPress themes")))
        return QStringLiteral("themes");
    if (jsonArrayContains(traits, QStringLiteral("Ecommerce")))
        return QStringLiteral("commerce");
    if (jsonArrayContains(traits, QStringLiteral("Caching")) || jsonArrayContains(traits, QStringLiteral("Performance")))
        return QStringLiteral("optimization");
    if (jsonArrayContains(traits, QStringLiteral("WordPress plugins"))
        || jsonArrayContains(traits, QStringLiteral("Form builders"))
        || jsonArrayContains(traits, QStringLiteral("Page builders")))
        return QStringLiteral("extensions");
    return component.value(QStringLiteral("category")).toString().trimmed().toLower();
}

QString technologyGroupLabel(const QString &key)
{
    if (key == QStringLiteral("web_application"))
        return QObject::tr("Web applications");
    if (key == QStringLiteral("framework"))
        return QObject::tr("Frameworks");
    if (key == QStringLiteral("extensions"))
        return QObject::tr("Plugins and forms");
    if (key == QStringLiteral("commerce"))
        return QObject::tr("Commerce");
    if (key == QStringLiteral("themes"))
        return QObject::tr("Themes");
    if (key == QStringLiteral("optimization"))
        return QObject::tr("Optimization");
    QString label = key;
    label.replace(QLatin1Char('_'), QLatin1Char(' '));
    if (!label.isEmpty())
        label[0] = label.at(0).toUpper();
    return label;
}

QString yesNo(bool value)
{
    return value ? QObject::tr("yes") : QObject::tr("no");
}

QString byteCount(int value)
{
    if (value >= 1024 * 1024)
        return QObject::tr("%1 MiB").arg(double(value) / (1024.0 * 1024.0), 0, 'f', 1);
    if (value >= 1024)
        return QObject::tr("%1 KiB").arg(double(value) / 1024.0, 0, 'f', 1);
    return QObject::tr("%1 B").arg(value);
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
    , m_lastSelectionView(nullptr)
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
    m_overview->setSelectionBehavior(QAbstractItemView::SelectItems);
    m_overview->setSelectionMode(QAbstractItemView::ExtendedSelection);
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
    m_stack->setSelectionBehavior(QAbstractItemView::SelectItems);
    m_stack->setSelectionMode(QAbstractItemView::ExtendedSelection);
    AdaptiveItemView::configure(m_stack, QStringLiteral("result/layout-v1/stack"), {2, 4, 4, 2});

    configureTable(m_evidence, {tr("Source"), tr("Subject"), tr("Field"), tr("Value")});
    m_evidence->setEditTriggers(QAbstractItemView::NoEditTriggers);
    AdaptiveItemView::configure(m_evidence, QStringLiteral("result/layout-v1/stack-evidence"), {2, 3, 3, 7});

    m_research->setColumnCount(2);
    m_research->setHeaderLabels({tr("Service"), tr("What it adds")});
    m_research->setRootIsDecorated(true);
    m_research->setAlternatingRowColors(true);
    m_research->setSelectionBehavior(QAbstractItemView::SelectItems);
    m_research->setSelectionMode(QAbstractItemView::ExtendedSelection);
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
    m_stackDetailTitle->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
    m_stackDetailSummary->setWordWrap(true);
    m_stackDetailSummary->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
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
        const QUrl url = researchUrl(m_research->currentIndex());
        if (!url.isEmpty())
            QGuiApplication::clipboard()->setText(url.toString());
    });

    const QList<QAbstractItemView *> structuredViews{
        m_overview, m_dns, m_compare, m_delegation, m_services, m_findings,
        m_stack, m_evidence, m_research, m_related, m_errors, m_contacts,
    };
    for (QAbstractItemView *view : structuredViews) {
        view->setContextMenuPolicy(Qt::CustomContextMenu);
        connect(view, &QAbstractItemView::customContextMenuRequested, this,
                [this, view](const QPoint &position) { showItemContextMenu(view, position); });
        connect(view->selectionModel(), &QItemSelectionModel::selectionChanged, this,
                [this, view] {
                    if (!view->selectionModel()->selectedIndexes().isEmpty())
                        m_lastSelectionView = view;
                    emit selectionAvailabilityChanged();
                });
        connect(view->selectionModel(), &QItemSelectionModel::currentChanged, this,
                [this, view](const QModelIndex &current) {
                    if (current.isValid())
                        m_lastSelectionView = view;
                    emit selectionAvailabilityChanged();
                });
    }
    for (QLabel *label : {m_stackDetailTitle, m_stackDetailSummary}) {
        label->setContextMenuPolicy(Qt::CustomContextMenu);
        connect(label, &QLabel::customContextMenuRequested, this,
                [this, label](const QPoint &position) { showLabelContextMenu(label, position); });
    }
    connect(m_rawText, &QPlainTextEdit::copyAvailable, this,
            [this] { emit selectionAvailabilityChanged(); });
    connect(m_tabs, &QTabWidget::currentChanged, this,
            [this] { emit selectionAvailabilityChanged(); });

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
    populateInvestigationOverview(report);
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

QString ResultWidget::fullResultText() const
{
    const QJsonObject value = m_item.contains(QStringLiteral("report"))
        ? m_item.value(QStringLiteral("report")).toObject()
        : m_item.value(QStringLiteral("result")).toObject();
    return QString::fromUtf8(QJsonDocument(value).toJson(QJsonDocument::Indented));
}

QAbstractItemView *ResultWidget::currentSelectionView() const
{
    QWidget *current = m_tabs->currentWidget();
    QWidget *focus = QApplication::focusWidget();
    if (current == m_stackPage) {
        if (focus && (focus == m_evidence || m_evidence->isAncestorOf(focus)))
            return m_evidence;
        if (focus && (focus == m_stack || m_stack->isAncestorOf(focus)))
            return m_stack;
        if (m_lastSelectionView == m_evidence && m_evidence->selectionModel()
            && !m_evidence->selectionModel()->selectedIndexes().isEmpty())
            return m_evidence;
        return m_stack;
    }
    if (current == m_researchPage)
        return m_research;
    const QList<QAbstractItemView *> directViews{
        m_overview, m_dns, m_compare, m_delegation, m_services, m_findings,
        m_related, m_errors, m_contacts,
    };
    for (QAbstractItemView *view : directViews) {
        if (current == view)
            return view;
    }
    return nullptr;
}

QString ResultWidget::selectionText() const
{
    QWidget *focus = QApplication::focusWidget();
    for (QLabel *label : {m_stackDetailTitle, m_stackDetailSummary}) {
        if (focus == label) {
            const QString selected = label->selectedText();
            return selected.isEmpty() ? label->text() : selected;
        }
    }
    if (focus && (focus == m_rawText || m_rawText->isAncestorOf(focus))) {
        const QTextCursor cursor = m_rawText->textCursor();
        return cursor.hasSelection() ? cursor.selectedText().replace(QChar::ParagraphSeparator, QLatin1Char('\n')) : QString();
    }
    return selectedItemViewText(currentSelectionView());
}

bool ResultWidget::hasSelection() const
{
    QWidget *focus = QApplication::focusWidget();
    for (QLabel *label : {m_stackDetailTitle, m_stackDetailSummary}) {
        if (focus == label)
            return !label->text().isEmpty();
    }
    if (focus && (focus == m_rawText || m_rawText->isAncestorOf(focus)))
        return m_rawText->textCursor().hasSelection();
    const QAbstractItemView *view = currentSelectionView();
    return view && view->selectionModel() && !view->selectionModel()->selectedIndexes().isEmpty();
}

void ResultWidget::showItemContextMenu(QAbstractItemView *view, const QPoint &position)
{
    if (!view || !view->selectionModel())
        return;
    const QModelIndex clicked = view->indexAt(position);
    if (!clicked.isValid())
        return;
    if (view->selectionModel()->isSelected(clicked))
        view->selectionModel()->setCurrentIndex(clicked, QItemSelectionModel::NoUpdate);
    else
        view->selectionModel()->setCurrentIndex(clicked, QItemSelectionModel::ClearAndSelect);

    QMenu menu(this);
    QAction *openLink = nullptr;
    QAction *copyLink = nullptr;
    QAction *investigate = nullptr;
    QUrl link;
    if (view == m_research) {
        link = researchUrl(clicked);
        if (!link.isEmpty()) {
            openLink = menu.addAction(tr("Open in Browser"));
            copyLink = menu.addAction(tr("Copy Link"));
        }
    } else if (view == m_related) {
        const QModelIndex hostnameIndex = clicked.siblingAtColumn(0);
        const QString hostname = hostnameIndex.data(Qt::DisplayRole).toString();
        if (!hostname.isEmpty())
            investigate = menu.addAction(tr("Investigate %1").arg(hostname));
    }

    const QString selected = selectedItemViewText(view);
    QAction *copy = nullptr;
    if (!selected.isEmpty()) {
        if (!menu.actions().isEmpty())
            menu.addSeparator();
        const bool multiple = view->selectionModel()->selectedIndexes().size() > 1;
        copy = menu.addAction(multiple ? tr("Copy Selection") : tr("Copy"));
    }
    if (menu.actions().isEmpty())
        return;

    QAction *chosen = menu.exec(view->viewport()->mapToGlobal(position));
    if (openLink && chosen == openLink)
        ExternalLinks::open(link, this);
    else if (copyLink && chosen == copyLink)
        QGuiApplication::clipboard()->setText(link.toString());
    else if (investigate && chosen == investigate)
        emit investigateRequested(clicked.siblingAtColumn(0).data(Qt::DisplayRole).toString());
    else if (copy && chosen == copy)
        QGuiApplication::clipboard()->setText(selected);
}

void ResultWidget::showLabelContextMenu(QLabel *label, const QPoint &position)
{
    if (!label)
        return;
    const QString selected = label->selectedText();
    const QString text = selected.isEmpty() ? label->text() : selected;
    if (text.isEmpty())
        return;
    QMenu menu(this);
    QAction *copy = menu.addAction(tr("Copy"));
    if (menu.exec(label->mapToGlobal(position)) == copy)
        QGuiApplication::clipboard()->setText(text);
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

void ResultWidget::populateInvestigationOverview(const QJsonObject &report)
{
    const QJsonObject investigation = report.value(QStringLiteral("investigation")).toObject();
    if (investigation.isEmpty())
        return;

    struct CategorySummary {
        QString label;
        QString key;
    };
    const QList<CategorySummary> categories{
        {tr("Web platform"), QStringLiteral("platform")},
        {tr("Commerce"), QStringLiteral("commerce")},
        {tr("Plugins and forms"), QStringLiteral("extensions")},
        {tr("Theme"), QStringLiteral("themes")},
        {tr("Optimization"), QStringLiteral("optimization")},
        {tr("Server / edge"), QStringLiteral("server")},
        {tr("Hosting"), QStringLiteral("hosting")},
        {tr("Network owner"), QStringLiteral("network")},
        {tr("DNS provider"), QStringLiteral("dns")},
        {tr("Mail"), QStringLiteral("mail")},
        {tr("Analytics / security"), QStringLiteral("analytics_security")},
        {tr("Other"), QStringLiteral("other")},
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
        QString summaryKey = technologyGroupKey(component);
        if (summaryKey == QStringLiteral("web_application") || summaryKey == QStringLiteral("framework"))
            summaryKey = QStringLiteral("platform");
        else if (summaryKey == QStringLiteral("web_server") || summaryKey == QStringLiteral("edge"))
            summaryKey = QStringLiteral("server");
        else if (summaryKey == QStringLiteral("analytics") || summaryKey == QStringLiteral("security"))
            summaryKey = QStringLiteral("analytics_security");
        int categoryIndex = categories.size() - 1;
        for (int index = 0; index < categories.size(); ++index) {
            if (categories.at(index).key == summaryKey || categories.at(index).key == category) {
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

    const QJsonObject homepage = investigation.value(QStringLiteral("homepage")).toObject();
    if (homepage.isEmpty())
        return;
    const QJsonObject assets = homepage.value(QStringLiteral("assets")).toObject();
    const QJsonObject metadata = homepage.value(QStringLiteral("metadata")).toObject();
    const QJsonObject security = homepage.value(QStringLiteral("security")).toObject();
    const QJsonObject accessibility = homepage.value(QStringLiteral("accessibility")).toObject();
    auto *homepageGroup = addGroup(m_overview, tr("Homepage observations"));
    QStringList responseParts{
        QString::number(homepage.value(QStringLiteral("status")).toInt()),
        homepage.value(QStringLiteral("http_version")).toString(),
        homepage.value(QStringLiteral("content_encoding")).toString(),
        byteCount(homepage.value(QStringLiteral("decoded_bytes")).toInt()),
    };
    responseParts.removeAll(QString());
    addValue(homepageGroup, tr("Response"), responseParts.join(QStringLiteral(" · ")));
    const bool markupAnalyzed = homepage.value(QStringLiteral("markup_analyzed")).toBool();
    if (markupAnalyzed) {
        addValue(homepageGroup, tr("Delivery"),
                 tr("HTML %1 · %2 scripts (%3 potentially blocking) · %4 styles · %5 third-party origins")
                     .arg(homepage.value(QStringLiteral("html_minification")).toString())
                     .arg(assets.value(QStringLiteral("scripts")).toInt())
                     .arg(assets.value(QStringLiteral("potentially_blocking_scripts")).toInt())
                     .arg(assets.value(QStringLiteral("stylesheets")).toInt())
                     .arg(assets.value(QStringLiteral("third_party_origin_total")).toInt()));
        addValue(homepageGroup, tr("SEO basics"),
                 tr("title %1 · description %2 · canonical %3 · viewport %4 · H1 %5 · JSON-LD %6")
                     .arg(yesNo(metadata.value(QStringLiteral("title")).toBool()))
                     .arg(yesNo(metadata.value(QStringLiteral("meta_description")).toBool()))
                     .arg(yesNo(!metadata.value(QStringLiteral("canonical_url")).toString().isEmpty()))
                     .arg(yesNo(metadata.value(QStringLiteral("viewport")).toBool()))
                     .arg(metadata.value(QStringLiteral("h1_count")).toInt())
                     .arg(metadata.value(QStringLiteral("structured_data")).toInt()));
    } else {
        addValue(homepageGroup, tr("Markup"), tr("Not analyzed; only response-header observations are available."));
    }
    int securityHeaders = 0;
    for (const QString &key : {QStringLiteral("hsts"), QStringLiteral("csp"), QStringLiteral("frame_protection"),
                               QStringLiteral("no_sniff"), QStringLiteral("referrer_policy"), QStringLiteral("permissions_policy")})
        securityHeaders += security.value(key).toBool() ? 1 : 0;
    addValue(homepageGroup, tr("Security headers"),
             tr("%1 of 6 observed · HTTPS %2 · mixed-content references %3")
                 .arg(securityHeaders).arg(yesNo(security.value(QStringLiteral("https")).toBool()))
                 .arg(security.value(QStringLiteral("mixed_content_references")).toInt()));
    if (markupAnalyzed) {
        addValue(homepageGroup, tr("Accessibility markers"),
                 tr("language %1 · missing alt %2/%3 · unlabeled controls %4/%5")
                     .arg(yesNo(accessibility.value(QStringLiteral("language")).toBool()))
                     .arg(accessibility.value(QStringLiteral("images_missing_alt")).toInt())
                     .arg(assets.value(QStringLiteral("images")).toInt())
                     .arg(accessibility.value(QStringLiteral("form_controls_missing_label")).toInt())
                     .arg(accessibility.value(QStringLiteral("form_controls")).toInt()));
    }
    const int homepageIndex = m_overview->indexOfTopLevelItem(homepageGroup);
    QTreeWidgetItem *homepageDetached = m_overview->takeTopLevelItem(homepageIndex);
    m_overview->insertTopLevelItem(qMin(2, m_overview->topLevelItemCount()), homepageDetached);
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
        const QString categoryKey = technologyGroupKey(component);
        QTreeWidgetItem *group = categories.value(categoryKey);
        if (!group) {
            group = addStackGroup(m_stack, technologyGroupLabel(categoryKey));
            categories.insert(categoryKey, group);
        }
        QString technologyName = component.value(QStringLiteral("name")).toString();
        const QString version = component.value(QStringLiteral("version")).toString();
        if (!version.isEmpty())
            technologyName += QStringLiteral(" ") + version;
        QString role = component.value(QStringLiteral("role")).toString();
        const QString parent = component.value(QStringLiteral("parent")).toString();
        if (!parent.isEmpty())
            role = role.isEmpty() ? parent : role + tr(" · %1").arg(parent);
        auto *technology = new QTreeWidgetItem(group, {QString(), technologyName,
                                                       role,
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
        QString title = payload.value(QStringLiteral("name")).toString();
        if (!payload.value(QStringLiteral("version")).toString().isEmpty())
            title += QStringLiteral(" ") + payload.value(QStringLiteral("version")).toString();
        m_stackDetailTitle->setText(title);
        QString summary = payload.value(QStringLiteral("summary")).toString();
        if (summary.isEmpty())
            summary = payload.value(QStringLiteral("role")).toString();
        QStringList context;
        if (!payload.value(QStringLiteral("parent")).toString().isEmpty())
            context.append(tr("Parent: %1").arg(payload.value(QStringLiteral("parent")).toString()));
        if (!payload.value(QStringLiteral("traits")).toArray().isEmpty())
            context.append(tr("Traits: %1").arg(joined(payload.value(QStringLiteral("traits")))));
        if (!payload.value(QStringLiteral("basis")).toArray().isEmpty())
            context.append(tr("Basis: %1").arg(joined(payload.value(QStringLiteral("basis")))));
        if (!context.isEmpty())
            summary += QStringLiteral("\n") + context.join(QStringLiteral(" · "));
        const int evidenceTotal = payload.value(QStringLiteral("evidence_total")).toInt(payload.value(QStringLiteral("evidence")).toArray().size());
        if (evidenceTotal > payload.value(QStringLiteral("evidence")).toArray().size())
            summary += tr("\nShowing %1 of %2 evidence signals.").arg(payload.value(QStringLiteral("evidence")).toArray().size()).arg(evidenceTotal);
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
    const bool valid = !researchUrl(m_research->currentIndex()).isEmpty();
    m_openResearch->setEnabled(valid);
    m_copyResearch->setEnabled(valid);
}

void ResultWidget::openSelectedResearchLink()
{
    const QUrl url = researchUrl(m_research->currentIndex());
    if (!url.isEmpty())
        ExternalLinks::open(url, this);
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
