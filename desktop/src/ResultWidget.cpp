#include "ResultWidget.h"

#include <QComboBox>
#include <QHeaderView>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonValue>
#include <QLabel>
#include <QPlainTextEdit>
#include <QStackedLayout>
#include <QTableWidget>
#include <QTabWidget>
#include <QTreeWidget>
#include <QVBoxLayout>

namespace {
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

}

ResultWidget::ResultWidget(QWidget *parent)
    : QWidget(parent)
    , m_tabs(new QTabWidget(this))
    , m_overview(new QTreeWidget(this))
    , m_dns(new QTableWidget(this))
    , m_contacts(new QTableWidget(this))
    , m_rawSource(new QComboBox(this))
    , m_rawText(new QPlainTextEdit(this))
    , m_emptyLabel(new QLabel(tr("Enter a domain, IP address, ASN, or URL to begin."), this))
{
    m_emptyLabel->setAlignment(Qt::AlignCenter);
    m_emptyLabel->setWordWrap(true);

    m_overview->setColumnCount(2);
    m_overview->setHeaderLabels({tr("Field"), tr("Value")});
    m_overview->setRootIsDecorated(true);
    m_overview->setAlternatingRowColors(true);
    m_overview->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_overview->header()->setSectionResizeMode(1, QHeaderView::Stretch);

    m_dns->setColumnCount(4);
    m_dns->setHorizontalHeaderLabels({tr("Type"), tr("Name"), tr("TTL"), tr("Value")});
    m_dns->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_dns->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_dns->setSortingEnabled(true);
    m_dns->setAlternatingRowColors(true);
    m_dns->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_dns->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_dns->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    m_dns->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);

    m_contacts->setColumnCount(6);
    m_contacts->setHorizontalHeaderLabels({tr("Role"), tr("Name"), tr("Handle"), tr("Email"), tr("Phone"), tr("Organization")});
    m_contacts->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_contacts->setSortingEnabled(true);
    m_contacts->setAlternatingRowColors(true);
    m_contacts->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_contacts->horizontalHeader()->setStretchLastSection(true);

    auto *rawPage = new QWidget(this);
    auto *rawLayout = new QVBoxLayout(rawPage);
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
    m_tabs->addTab(m_dns, tr("DNS"));
    m_tabs->addTab(m_contacts, tr("Contacts"));
    m_tabs->addTab(rawPage, tr("Raw"));

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
    if (auto *stack = qobject_cast<QStackedLayout *>(layout()))
        stack->setCurrentWidget(m_tabs);
}

void ResultWidget::showDNSTab()
{
    m_tabs->setCurrentWidget(m_dns);
}

QString ResultWidget::copyText() const
{
    if (m_tabs->currentIndex() == 3 && !m_rawText->toPlainText().isEmpty())
        return m_rawText->toPlainText();
    return QString::fromUtf8(QJsonDocument(m_item.value(QStringLiteral("result")).toObject()).toJson(QJsonDocument::Indented));
}

QString ResultWidget::currentTarget() const
{
    return m_item.value(QStringLiteral("input")).toString();
}

int ResultWidget::dnsRowCount() const
{
    return m_dns->rowCount();
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
        for (const QJsonValue &value : events) {
            const QJsonObject event = value.toObject();
            addValue(timeline, event.value(QStringLiteral("action")).toString(), event.value(QStringLiteral("date")).toString());
        }
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

void ResultWidget::populateDNS(const QJsonObject &result)
{
    m_dns->setSortingEnabled(false);
    m_dns->setRowCount(0);
    const QJsonArray records = result.value(QStringLiteral("dns")).toObject().value(QStringLiteral("records")).toArray();
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
