#include "AdvancedDialog.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QTreeWidget>
#include <QUrl>
#include <QVBoxLayout>

AdvancedDialog::AdvancedDialog(QWidget *parent)
    : QDialog(parent)
    , m_protocol(new QComboBox(this))
    , m_fallback(new QComboBox(this))
    , m_server(new QLineEdit(this))
    , m_resolver(new QLineEdit(this))
    , m_strategy(new QComboBox(this))
    , m_timeout(new QSpinBox(this))
    , m_refresh(new QCheckBox(tr("Refresh IANA RDAP service data"), this))
    , m_dnssec(new QCheckBox(tr("Request DNSSEC records"), this))
    , m_globalping(new QCheckBox(tr("Remote DNS probes via Globalping (shares the target)"), this))
    , m_trace(new QCheckBox(tr("Include a local network path trace in Diagnose"), this))
    , m_otx(new QCheckBox(tr("Use AlienVault OTX passive DNS in Investigate (shares discovered IPs)"), this))
    , m_relatedLimit(new QSpinBox(this))
    , m_researchLinksSummary(new QLabel(this))
    , m_researchLinksButton(new QPushButton(tr("Choose…"), this))
    , m_investigationLink(new QLineEdit(this))
    , m_otxEndpoint(new QLineEdit(this))
    , m_buttons(new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this))
{
    setWindowTitle(tr("Advanced Lookup"));
    m_protocol->addItem(tr("Automatic"), QStringLiteral("auto"));
    m_protocol->addItem(QStringLiteral("RDAP"), QStringLiteral("rdap"));
    m_protocol->addItem(QStringLiteral("WHOIS"), QStringLiteral("whois"));
    m_protocol->addItem(QStringLiteral("RWhois"), QStringLiteral("rwhois"));
    m_fallback->addItem(tr("Only when unavailable"), QStringLiteral("unavailable"));
    m_fallback->addItem(tr("Strict — no fallback"), QStringLiteral("none"));
    m_fallback->addItem(tr("Try both after any error"), QStringLiteral("any-error"));
    m_server->setPlaceholderText(tr("Optional host or RDAP URL"));
    m_resolver->setPlaceholderText(tr("system, tls://dns.example, https://…"));
    m_resolver->setToolTip(tr("Comma-separated resolver URIs. Leave empty to use the system resolver."));
    m_strategy->addItem(tr("First successful"), QStringLiteral("first"));
    m_strategy->addItem(tr("Query all"), QStringLiteral("all"));
    m_strategy->addItem(tr("Fastest"), QStringLiteral("fastest"));
    m_strategy->addItem(tr("Random"), QStringLiteral("random"));
    m_strategy->addItem(tr("Consensus"), QStringLiteral("consensus"));
    m_timeout->setRange(1, 600);
    m_timeout->setValue(15);
    m_timeout->setSuffix(tr(" seconds"));
    m_relatedLimit->setRange(1, 100);
    m_relatedLimit->setValue(25);
    m_investigationLink->setPlaceholderText(tr("Optional HTTPS template or off"));
    m_investigationLink->setToolTip(tr("Custom links must contain {type} and {value}. They are shown but never opened automatically."));
    m_otxEndpoint->setPlaceholderText(QStringLiteral("https://otx.alienvault.com/api/v1"));
    m_otxEndpoint->setToolTip(tr("Optional OTX-compatible API base URL. API keys are read only from WHODIS_OTX_API_KEY."));

    auto *form = new QFormLayout;
    form->addRow(tr("Protocol:"), m_protocol);
    form->addRow(tr("Direct server:"), m_server);
    form->addRow(tr("Fallback:"), m_fallback);
    form->addRow(tr("DNS resolvers:"), m_resolver);
    form->addRow(tr("Resolver strategy:"), m_strategy);
    form->addRow(QString(), m_dnssec);
    form->addRow(QString(), m_globalping);
    form->addRow(QString(), m_trace);
    form->addRow(QString(), m_otx);
    form->addRow(tr("Related results:"), m_relatedLimit);
    auto *researchLinks = new QWidget(this);
    auto *researchLinksLayout = new QHBoxLayout(researchLinks);
    researchLinksLayout->setContentsMargins(0, 0, 0, 0);
    researchLinksLayout->addWidget(m_researchLinksSummary, 1);
    researchLinksLayout->addWidget(m_researchLinksButton);
    form->addRow(tr("Research services:"), researchLinks);
    form->addRow(tr("Custom research link:"), m_investigationLink);
    form->addRow(tr("OTX endpoint:"), m_otxEndpoint);
    form->addRow(tr("Timeout:"), m_timeout);
    form->addRow(QString(), m_refresh);

    auto *note = new QLabel(tr("Normal lookups should use Automatic. Direct servers and RWhois are intended for diagnostics and delegated authorities."), this);
    note->setWordWrap(true);
    auto *layout = new QVBoxLayout(this);
    layout->addWidget(note);
    layout->addLayout(form);
    layout->addWidget(m_buttons);

    connect(m_protocol, &QComboBox::currentIndexChanged, this, &AdvancedDialog::updateState);
    connect(m_server, &QLineEdit::textChanged, this, &AdvancedDialog::updateState);
    connect(m_researchLinksButton, &QPushButton::clicked, this, &AdvancedDialog::chooseResearchLinks);
    connect(m_investigationLink, &QLineEdit::textChanged, this, &AdvancedDialog::updateState);
    connect(m_otxEndpoint, &QLineEdit::textChanged, this, &AdvancedDialog::updateState);
    connect(m_buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(m_buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    updateState();
}

QJsonObject AdvancedDialog::options() const
{
    QJsonObject result{
        {QStringLiteral("protocol"), m_protocol->currentData().toString()},
        {QStringLiteral("fallback"), m_fallback->currentData().toString()},
        {QStringLiteral("timeout_ms"), m_timeout->value() * 1000},
    };
    if (!m_server->text().trimmed().isEmpty())
        result.insert(QStringLiteral("server"), m_server->text().trimmed());
    QJsonObject dns;
    QJsonArray resolvers;
    for (const QString &entry : m_resolver->text().split(',', Qt::SkipEmptyParts)) {
        if (!entry.trimmed().isEmpty())
            resolvers.append(entry.trimmed());
    }
    if (!resolvers.isEmpty())
        dns.insert(QStringLiteral("resolvers"), resolvers);
    dns.insert(QStringLiteral("strategy"), m_strategy->currentData().toString());
    if (m_dnssec->isChecked())
        dns.insert(QStringLiteral("edns"), QJsonObject{{QStringLiteral("dnssec"), true}});
    if (m_globalping->isChecked())
        dns.insert(QStringLiteral("globalping"), true);
    result.insert(QStringLiteral("dns"), dns);
    if (m_globalping->isChecked() || m_trace->isChecked())
        result.insert(QStringLiteral("diagnose"), QJsonObject{{QStringLiteral("remote"), m_globalping->isChecked()},
                                                               {QStringLiteral("trace"), m_trace->isChecked()}});
    if (m_refresh->isChecked())
        result.insert(QStringLiteral("refresh_bootstrap"), true);
    QJsonObject investigation{{QStringLiteral("related_limit"), m_relatedLimit->value()}};
    if (!m_researchLinks.isEmpty() && m_investigationLink->text().trimmed().compare(QStringLiteral("off"), Qt::CaseInsensitive) != 0) {
        QJsonArray linkProviders;
        for (const QString &provider : m_researchLinks)
            linkProviders.append(provider);
        investigation.insert(QStringLiteral("link_providers"), linkProviders);
    }
    if (!m_investigationLink->text().trimmed().isEmpty())
        investigation.insert(QStringLiteral("external_link_template"), m_investigationLink->text().trimmed());
    if (!m_otxEndpoint->text().trimmed().isEmpty())
        investigation.insert(QStringLiteral("otx_endpoint"), m_otxEndpoint->text().trimmed());
    if (m_otx->isChecked())
        investigation.insert(QStringLiteral("enrichments"), QJsonArray{QStringLiteral("otx")});
    result.insert(QStringLiteral("investigation"), investigation);
    return result;
}

QJsonObject AdvancedDialog::persistentOptions() const
{
    QJsonObject result = options();
    QJsonObject investigation = result.value(QStringLiteral("investigation")).toObject();
    investigation.remove(QStringLiteral("enrichments"));
    result.insert(QStringLiteral("investigation"), investigation);
    return result;
}

void AdvancedDialog::setOptions(const QJsonObject &options)
{
    const auto selectValue = [](QComboBox *combo, const QString &value) {
        const int index = combo->findData(value);
        if (index >= 0)
            combo->setCurrentIndex(index);
    };
    selectValue(m_protocol, options.value(QStringLiteral("protocol")).toString(QStringLiteral("auto")));
    selectValue(m_fallback, options.value(QStringLiteral("fallback")).toString(QStringLiteral("unavailable")));
    m_server->setText(options.value(QStringLiteral("server")).toString());
    const QJsonObject dns = options.value(QStringLiteral("dns")).toObject();
    QStringList resolvers;
    for (const QJsonValue &entry : dns.value(QStringLiteral("resolvers")).toArray())
        resolvers.append(entry.toString());
    if (resolvers.isEmpty() && options.contains(QStringLiteral("resolver")))
        resolvers.append(options.value(QStringLiteral("resolver")).toString());
    m_resolver->setText(resolvers.join(QStringLiteral(", ")));
    selectValue(m_strategy, dns.value(QStringLiteral("strategy")).toString(QStringLiteral("first")));
    m_dnssec->setChecked(dns.value(QStringLiteral("edns")).toObject().value(QStringLiteral("dnssec")).toBool());
    m_globalping->setChecked(dns.value(QStringLiteral("globalping")).toBool()
                             || options.value(QStringLiteral("diagnose")).toObject().value(QStringLiteral("remote")).toBool());
    m_trace->setChecked(options.value(QStringLiteral("diagnose")).toObject().value(QStringLiteral("trace")).toBool());
    const QJsonObject investigation = options.value(QStringLiteral("investigation")).toObject();
    m_relatedLimit->setValue(investigation.value(QStringLiteral("related_limit")).toInt(25));
    m_investigationLink->setText(investigation.value(QStringLiteral("external_link_template")).toString());
    m_researchLinks.clear();
    if (investigation.contains(QStringLiteral("link_providers"))) {
        for (const QJsonValue &value : investigation.value(QStringLiteral("link_providers")).toArray()) {
            if (!value.toString().trimmed().isEmpty())
                m_researchLinks.append(value.toString().trimmed().toLower());
        }
    }
    if (m_researchLinks.isEmpty() && m_investigationLink->text().trimmed().isEmpty()) {
        m_researchLinks.append(QStringLiteral("core"));
    }
    m_otxEndpoint->setText(investigation.value(QStringLiteral("otx_endpoint")).toString());
    bool otx = false;
    for (const QJsonValue &value : investigation.value(QStringLiteral("enrichments")).toArray())
        otx = otx || value.toString().compare(QStringLiteral("otx"), Qt::CaseInsensitive) == 0;
    m_otx->setChecked(otx);
    m_timeout->setValue(qMax(1, options.value(QStringLiteral("timeout_ms")).toInt(15000) / 1000));
    m_refresh->setChecked(options.value(QStringLiteral("refresh_bootstrap")).toBool());
    updateState();
}

void AdvancedDialog::setInvestigationLinkProviders(const QJsonArray &providers)
{
    m_investigationLinkProviders = providers;
    updateState();
}

void AdvancedDialog::chooseResearchLinks()
{
    if (m_investigationLinkProviders.isEmpty())
        return;

    QDialog dialog(this);
    dialog.setWindowTitle(tr("Research services"));
    dialog.resize(720, 480);
    auto *layout = new QVBoxLayout(&dialog);
    auto *note = new QLabel(tr("Whodis creates these links locally. A service receives the domain or IP only when you explicitly open its link."), &dialog);
    note->setWordWrap(true);
    layout->addWidget(note);

    auto *tree = new QTreeWidget(&dialog);
    tree->setColumnCount(3);
    tree->setHeaderLabels({tr("Service"), tr("Targets"), tr("What it adds")});
    tree->setRootIsDecorated(true);
    tree->setAlternatingRowColors(true);
    tree->header()->setStretchLastSection(true);
    QTreeWidgetItem *coreGroup = new QTreeWidgetItem(tree, {tr("Core")});
    QTreeWidgetItem *moreGroup = new QTreeWidgetItem(tree, {tr("More")});
    for (QTreeWidgetItem *group : {coreGroup, moreGroup}) {
        QFont font = group->font(0);
        font.setBold(true);
        group->setFont(0, font);
        group->setFlags(group->flags() & ~Qt::ItemIsSelectable);
        group->setExpanded(true);
    }

    QStringList selected;
    if (m_researchLinks.contains(QStringLiteral("all"), Qt::CaseInsensitive)) {
        for (const QJsonValue &value : m_investigationLinkProviders)
            selected.append(value.toObject().value(QStringLiteral("id")).toString());
    } else if (!m_researchLinks.contains(QStringLiteral("off"), Qt::CaseInsensitive)) {
        if (m_researchLinks.contains(QStringLiteral("core"), Qt::CaseInsensitive)) {
            for (const QJsonValue &value : m_investigationLinkProviders) {
                const QJsonObject provider = value.toObject();
                if (provider.value(QStringLiteral("tier")).toString() == QStringLiteral("core"))
                    selected.append(provider.value(QStringLiteral("id")).toString());
            }
        } else {
            selected = m_researchLinks;
        }
    }

    for (const QJsonValue &value : m_investigationLinkProviders) {
        const QJsonObject provider = value.toObject();
        QTreeWidgetItem *group = provider.value(QStringLiteral("tier")).toString() == QStringLiteral("core") ? coreGroup : moreGroup;
        QStringList targets;
        for (const QJsonValue &target : provider.value(QStringLiteral("targets")).toArray())
            targets.append(target.toString().toUpper());
        auto *item = new QTreeWidgetItem(group, {provider.value(QStringLiteral("label")).toString(), targets.join(QStringLiteral(", ")), provider.value(QStringLiteral("purpose")).toString()});
        item->setData(0, Qt::UserRole, provider.value(QStringLiteral("id")).toString());
        item->setFlags(item->flags() | Qt::ItemIsUserCheckable);
        item->setCheckState(0, selected.contains(provider.value(QStringLiteral("id")).toString(), Qt::CaseInsensitive) ? Qt::Checked : Qt::Unchecked);
    }
    tree->resizeColumnToContents(0);
    tree->resizeColumnToContents(1);
    layout->addWidget(tree, 1);

    auto *presets = new QHBoxLayout;
    auto *core = new QPushButton(tr("Core defaults"), &dialog);
    auto *all = new QPushButton(tr("Select all"), &dialog);
    auto *none = new QPushButton(tr("Select none"), &dialog);
    presets->addWidget(core);
    presets->addWidget(all);
    presets->addWidget(none);
    presets->addStretch();
    layout->addLayout(presets);
    const auto setChecks = [tree](bool includeCore, bool includeMore) {
        for (int groupIndex = 0; groupIndex < tree->topLevelItemCount(); ++groupIndex) {
            QTreeWidgetItem *group = tree->topLevelItem(groupIndex);
            const bool checked = groupIndex == 0 ? includeCore : includeMore;
            for (int index = 0; index < group->childCount(); ++index)
                group->child(index)->setCheckState(0, checked ? Qt::Checked : Qt::Unchecked);
        }
    };
    connect(core, &QPushButton::clicked, &dialog, [setChecks] { setChecks(true, false); });
    connect(all, &QPushButton::clicked, &dialog, [setChecks] { setChecks(true, true); });
    connect(none, &QPushButton::clicked, &dialog, [setChecks] { setChecks(false, false); });

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    layout->addWidget(buttons);
    if (dialog.exec() != QDialog::Accepted)
        return;

    QStringList chosen;
    QStringList coreIDs;
    QStringList allIDs;
    for (int groupIndex = 0; groupIndex < tree->topLevelItemCount(); ++groupIndex) {
        QTreeWidgetItem *group = tree->topLevelItem(groupIndex);
        for (int index = 0; index < group->childCount(); ++index) {
            QTreeWidgetItem *item = group->child(index);
            const QString id = item->data(0, Qt::UserRole).toString();
            allIDs.append(id);
            if (groupIndex == 0)
                coreIDs.append(id);
            if (item->checkState(0) == Qt::Checked)
                chosen.append(id);
        }
    }
    if (chosen.isEmpty())
        m_researchLinks = {QStringLiteral("off")};
    else if (chosen == allIDs)
        m_researchLinks = {QStringLiteral("all")};
    else if (chosen == coreIDs)
        m_researchLinks = {QStringLiteral("core")};
    else
        m_researchLinks = chosen;
    updateState();
}

void AdvancedDialog::updateState()
{
    const QString protocol = m_protocol->currentData().toString();
    m_server->setEnabled(protocol != QStringLiteral("auto"));
    if (protocol == QStringLiteral("auto"))
        m_server->clear();
    const QString linkText = m_investigationLink->text().trimmed();
    const QUrl link(linkText);
    const bool linkValid = linkText.isEmpty() || linkText.compare(QStringLiteral("off"), Qt::CaseInsensitive) == 0
        || (link.isValid() && link.scheme() == QStringLiteral("https") && !link.host().isEmpty() && link.userInfo().isEmpty()
            && linkText.contains(QStringLiteral("{type}")) && linkText.contains(QStringLiteral("{value}")));
    const QString endpointText = m_otxEndpoint->text().trimmed();
    const QUrl endpoint(endpointText);
    const bool endpointValid = endpointText.isEmpty()
        || (endpoint.isValid() && endpoint.scheme() == QStringLiteral("https") && !endpoint.host().isEmpty()
            && endpoint.userInfo().isEmpty() && endpoint.query().isEmpty() && endpoint.fragment().isEmpty());
    const bool serverValid = protocol != QStringLiteral("rwhois") || !m_server->text().trimmed().isEmpty();
    const bool valid = serverValid && linkValid && endpointValid;
    const bool linksDisabled = linkText.compare(QStringLiteral("off"), Qt::CaseInsensitive) == 0;
    m_researchLinksButton->setEnabled(!m_investigationLinkProviders.isEmpty() && !linksDisabled);
    if (linksDisabled)
        m_researchLinksSummary->setText(tr("Off"));
    else if (m_researchLinks.contains(QStringLiteral("all"), Qt::CaseInsensitive))
        m_researchLinksSummary->setText(tr("All services"));
    else if (m_researchLinks.contains(QStringLiteral("off"), Qt::CaseInsensitive))
        m_researchLinksSummary->setText(tr("Off"));
    else if (m_researchLinks.contains(QStringLiteral("core"), Qt::CaseInsensitive))
        m_researchLinksSummary->setText(tr("Core services"));
    else if (!m_researchLinks.isEmpty())
        m_researchLinksSummary->setText(tr("Custom (%1)").arg(m_researchLinks.size()));
    else
        m_researchLinksSummary->setText(tr("Custom link only"));
    m_buttons->button(QDialogButtonBox::Ok)->setEnabled(valid);
    m_buttons->button(QDialogButtonBox::Ok)->setToolTip(!serverValid ? tr("RWhois requires a direct server.")
                                                          : !linkValid ? tr("The custom research link must be off or an HTTPS template containing {type} and {value}.")
                                                                       : !endpointValid ? tr("The OTX endpoint must be an HTTPS URL without credentials, query, or fragment.") : QString());
}
