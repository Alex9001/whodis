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
    QString copyText() const;
    QString currentTarget() const;
    int dnsRowCount() const;

private:
    void populateOverview(const QJsonObject &result);
    void populateDNS(const QJsonObject &result);
    void populateContacts(const QJsonObject &result);
    void populateRaw(const QJsonArray &sources);

    QTabWidget *m_tabs;
    QTreeWidget *m_overview;
    QTableWidget *m_dns;
    QTableWidget *m_contacts;
    QComboBox *m_rawSource;
    QPlainTextEdit *m_rawText;
    QLabel *m_emptyLabel;
    QJsonObject m_item;
};

