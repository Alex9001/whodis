#pragma once

#include <QJsonObject>
#include <QMainWindow>

class QAction;
class AdvancedDialog;
class EngineClient;
class QLineEdit;
class QProgressBar;
class QPushButton;
class QTimer;
class ResultWidget;

class MainWindow final : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);

protected:
    void closeEvent(QCloseEvent *event) override;

private slots:
    void scheduleValidation();
    void validateTarget();
    void runLookup();
    void runDNSScan();
    void runDNSQuery();
    void runDNSCompare();
    void runDNSTrace();
    void runDiagnose();
    void runAXFR();
    void cancelLookup();
    void openBatch();
    void openAdvanced();
    void copyCurrent();
    void saveCurrent();
    void handleResponse(const QString &id, const QString &method, const QJsonValue &result);
    void handleFailure(const QString &id, const QString &method, const QString &message);
    void handleProgress(const QJsonObject &progress);

private:
    void startOperation(const QString &operation);
    void setBusy(bool busy);
    void updateActionState();

    EngineClient *m_engine;
    AdvancedDialog *m_advanced;
    QLineEdit *m_target;
    QPushButton *m_lookup;
    QPushButton *m_scan;
    QPushButton *m_dns;
    QPushButton *m_diagnose;
    QPushButton *m_batch;
    QPushButton *m_cancel;
    QProgressBar *m_progress;
    ResultWidget *m_result;
    QTimer *m_validationTimer;
    QAction *m_saveAction;
    QAction *m_copyAction;
    QAction *m_axfrAction;
    QAction *m_compareAction;
    QAction *m_traceAction;
    QString m_parseRequest;
    QString m_lookupRequest;
    QString m_exportRequest;
    QString m_exportPath;
    QString m_resultToken;
    QString m_validKind;
};
