#pragma once

#include <QDialog>
#include <QJsonArray>
#include <QJsonObject>
#include <QStringList>

class QCheckBox;
class QComboBox;
class QDialogButtonBox;
class QLineEdit;
class QLabel;
class QPushButton;
class QSpinBox;

class AdvancedDialog final : public QDialog
{
    Q_OBJECT

public:
    explicit AdvancedDialog(QWidget *parent = nullptr);
    QJsonObject options() const;
    QJsonObject persistentOptions() const;
    void setOptions(const QJsonObject &options);
    void setInvestigationLinkProviders(const QJsonArray &providers);

private slots:
    void updateState();
    void chooseResearchLinks();

private:
    QComboBox *m_protocol;
    QComboBox *m_fallback;
    QLineEdit *m_server;
    QLineEdit *m_resolver;
    QComboBox *m_strategy;
    QSpinBox *m_timeout;
    QCheckBox *m_refresh;
    QCheckBox *m_dnssec;
    QCheckBox *m_globalping;
    QCheckBox *m_trace;
    QCheckBox *m_otx;
    QSpinBox *m_relatedLimit;
    QLabel *m_researchLinksSummary;
    QPushButton *m_researchLinksButton;
    QLineEdit *m_investigationLink;
    QLineEdit *m_otxEndpoint;
    QDialogButtonBox *m_buttons;
    QJsonArray m_investigationLinkProviders;
    QStringList m_researchLinks{QStringLiteral("core")};
};
