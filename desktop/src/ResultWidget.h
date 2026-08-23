#pragma once

#include <QJsonObject>
#include <QWidget>

class QComboBox;
class QHBoxLayout;
class QLabel;
class QPlainTextEdit;
class QPushButton;
class QSplitter;
class QTableWidget;
class QTabWidget;
class QTreeWidget;
class QTreeWidgetItem;

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
    QString currentRawSource() const;
    bool hasRawSource() const;
    int dnsRowCount() const;
    int relatedRowCount() const;

signals:
    void investigateRequested(const QString &target);

private:
    void populateOverview(const QJsonObject &result);
    void populateInvestigationOverview(const QJsonObject &investigation);
    void populateDNS(const QJsonObject &result);
    void populateReportDNS(const QJsonObject &report);
    void populateCompare(const QJsonObject &report);
    void populateDelegation(const QJsonObject &report);
    void populateServices(const QJsonObject &report);
    void populateFindings(const QJsonObject &report);
    void populateInvestigation(const QJsonObject &report);
    void populateErrors(const QJsonObject &report);
    void populateContacts(const QJsonObject &result);
    void populateRaw(const QJsonArray &sources);
    void clearStackDetails();
    void showStackDetails(QTreeWidgetItem *item);
    void refreshViews();

    QTabWidget *m_tabs;
    QTreeWidget *m_overview;
    QTableWidget *m_dns;
    QTableWidget *m_compare;
    QTableWidget *m_delegation;
    QTableWidget *m_services;
    QTableWidget *m_findings;
    QTreeWidget *m_stack;
    QWidget *m_stackPage;
    QSplitter *m_stackSplitter;
    QLabel *m_stackDetailTitle;
    QLabel *m_stackDetailSummary;
    QTableWidget *m_evidence;
    QWidget *m_stackActions;
    QHBoxLayout *m_stackActionsLayout;
    QTableWidget *m_related;
    QTableWidget *m_errors;
    QTableWidget *m_contacts;
    QComboBox *m_rawSource;
    QPlainTextEdit *m_rawText;
    QWidget *m_rawPage;
    QLabel *m_emptyLabel;
    QJsonObject m_item;
};
