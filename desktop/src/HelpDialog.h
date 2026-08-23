#pragma once

#include <QDialog>
#include <QVector>

class QCloseEvent;
class QLineEdit;
class QListWidget;
class QTextBrowser;
class QUrl;

class HelpDialog final : public QDialog
{
    Q_OBJECT

public:
    explicit HelpDialog(QWidget *parent = nullptr);

    int topicCount() const;
    QString currentTitle() const;
    void setSearchText(const QString &text);

protected:
    void closeEvent(QCloseEvent *event) override;

private slots:
    void filterTopics(const QString &text);
    void showSelectedTopic();
    void openLink(const QUrl &url);

private:
    struct Topic {
        QString id;
        QString title;
        QString summary;
        QString body;
    };

    void loadTopics();
    void restoreSelection();

    QLineEdit *m_search;
    QListWidget *m_topics;
    QTextBrowser *m_content;
    QVector<Topic> m_catalog;
};
