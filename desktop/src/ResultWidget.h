#pragma once

#include <QJsonObject>
#include <QWidget>

class QComboBox;
class QLabel;
class QPlainTextEdit;
class QTableWidget;
class QTabWidget;
class QTreeWidget;

class ResultWidget final : public QWidget
{
    Q_OBJECT

public:
    explicit ResultWidget(QWidget *parent = nullptr);

    void clearResult();
    void setItem(const QJsonObject &item);
    void setReportItem(const QJsonObject &item);
    void showDNSTab();
    QString copyText() const;
    QString currentTarget() const;
    int dnsRowCount() const;

private:
    void populateOverview(const QJsonObject &result);
    void populateDNS(const QJsonObject &result);
    void populateReportDNS(const QJsonObject &report);
    void populateCompare(const QJsonObject &report);
    void populateDelegation(const QJsonObject &report);
    void populateServices(const QJsonObject &report);
    void populateFindings(const QJsonObject &report);
    void populateContacts(const QJsonObject &result);
    void populateRaw(const QJsonArray &sources);

    QTabWidget *m_tabs;
    QTreeWidget *m_overview;
    QTableWidget *m_dns;
    QTableWidget *m_compare;
    QTableWidget *m_delegation;
    QTableWidget *m_services;
    QTableWidget *m_findings;
    QTableWidget *m_contacts;
    QComboBox *m_rawSource;
    QPlainTextEdit *m_rawText;
    QWidget *m_rawPage;
    QLabel *m_emptyLabel;
    QJsonObject m_item;
};
