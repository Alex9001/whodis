#include "AdvancedDialog.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QJsonArray>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
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

    auto *form = new QFormLayout;
    form->addRow(tr("Protocol:"), m_protocol);
    form->addRow(tr("Direct server:"), m_server);
    form->addRow(tr("Fallback:"), m_fallback);
    form->addRow(tr("DNS resolvers:"), m_resolver);
    form->addRow(tr("Resolver strategy:"), m_strategy);
    form->addRow(QString(), m_dnssec);
    form->addRow(QString(), m_globalping);
    form->addRow(QString(), m_trace);
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
    m_timeout->setValue(qMax(1, options.value(QStringLiteral("timeout_ms")).toInt(15000) / 1000));
    m_refresh->setChecked(options.value(QStringLiteral("refresh_bootstrap")).toBool());
    updateState();
}

void AdvancedDialog::updateState()
{
    const QString protocol = m_protocol->currentData().toString();
    m_server->setEnabled(protocol != QStringLiteral("auto"));
    if (protocol == QStringLiteral("auto"))
        m_server->clear();
    const bool valid = protocol != QStringLiteral("rwhois") || !m_server->text().trimmed().isEmpty();
    m_buttons->button(QDialogButtonBox::Ok)->setEnabled(valid);
}
