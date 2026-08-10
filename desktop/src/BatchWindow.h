#pragma once

#include <QJsonObject>
#include <QMainWindow>
#include <QVector>

class EngineClient;
class QComboBox;
class QPlainTextEdit;
class QProgressBar;
class QPushButton;
class QSpinBox;
class QTableWidget;
class ResultWidget;

class BatchWindow final : public QMainWindow
{
    Q_OBJECT

public:
    explicit BatchWindow(QWidget *parent = nullptr);

protected:
    void closeEvent(QCloseEvent *event) override;

private slots:
    void importTargets();
    void startLookup();
    void cancelLookup();
    void retryFailed();
    void exportResults();
    void handleResponse(const QString &id, const QString &method, const QJsonValue &result);
    void handleFailure(const QString &id, const QString &method, const QString &message);
    void handleProgress(const QJsonObject &progress);
    void showSelectedResult();

private:
    QStringList targetsFromEditor() const;
    void beginLookup(const QStringList &targets);
    void updateRow(int index, const QJsonObject &item);
    int rowForIndex(int index) const;
    void finishLookup(bool canceled = false);
    void setBusy(bool busy);

    EngineClient *m_engine;
    QPlainTextEdit *m_targets;
    QComboBox *m_mode;
    QSpinBox *m_workers;
    QPushButton *m_start;
    QPushButton *m_cancel;
    QPushButton *m_retry;
    QPushButton *m_export;
    QProgressBar *m_progress;
    QTableWidget *m_table;
    ResultWidget *m_result;
    QVector<QJsonObject> m_items;
    QString m_activeRequest;
    QString m_token;
    QString m_exportRequest;
    QString m_exportPath;
    bool m_cancelRequested = false;
};
