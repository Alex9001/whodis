#pragma once

#include <QHash>
#include <QJsonObject>
#include <QObject>
#include <QProcess>

class EngineClient final : public QObject
{
    Q_OBJECT

public:
    explicit EngineClient(QObject *parent = nullptr);
    ~EngineClient() override;

    void start();
    bool isReady() const;
    QString request(const QString &method, const QJsonObject &params = {});
    void cancel(const QString &requestId);

signals:
    void engineReady(const QString &version, int protocolVersion);
    void engineUnavailable(const QString &message);
    void responseReceived(const QString &requestId, const QString &method, const QJsonValue &result);
    void requestFailed(const QString &requestId, const QString &method, const QString &message);
    void progressReceived(const QJsonObject &progress);

private slots:
    void readOutput();
    void readError();
    void processFinished(int exitCode, QProcess::ExitStatus status);

private:
    QString locateEngine() const;
    void processLine(const QByteArray &line);
    void sendObject(const QJsonObject &message);

    QProcess m_process;
    QByteArray m_outputBuffer;
    QHash<QString, QString> m_methods;
    quint64 m_nextId = 0;
    bool m_ready = false;
    bool m_restarted = false;
};
