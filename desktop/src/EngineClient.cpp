#include "EngineClient.h"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QStandardPaths>

namespace {
constexpr int supportedProtocolVersion = 4;
}

EngineClient::EngineClient(QObject *parent)
    : QObject(parent)
{
    m_process.setProcessChannelMode(QProcess::SeparateChannels);
    connect(&m_process, &QProcess::readyReadStandardOutput, this, &EngineClient::readOutput);
    connect(&m_process, &QProcess::readyReadStandardError, this, &EngineClient::readError);
    connect(&m_process, qOverload<int, QProcess::ExitStatus>(&QProcess::finished),
            this, &EngineClient::processFinished);
    connect(&m_process, &QProcess::errorOccurred, this, [this](QProcess::ProcessError) {
        if (m_process.state() == QProcess::NotRunning) {
            emit engineUnavailable(tr("Could not start the Whodis engine: %1").arg(m_process.errorString()));
        }
    });
}

EngineClient::~EngineClient()
{
    if (m_process.state() == QProcess::NotRunning)
        return;
    disconnect(&m_process, nullptr, this, nullptr);
    m_process.closeWriteChannel();
    if (!m_process.waitForFinished(1000)) {
        m_process.terminate();
        if (!m_process.waitForFinished(500)) {
            m_process.kill();
            m_process.waitForFinished(500);
        }
    }
}

void EngineClient::start()
{
    if (m_process.state() != QProcess::NotRunning)
        return;
    const QString engine = locateEngine();
    if (engine.isEmpty()) {
        emit engineUnavailable(tr("The private whodis-gui-engine executable could not be found."));
        return;
    }
    m_ready = false;
    m_process.start(engine, {});
    if (!m_process.waitForStarted(3000)) {
        emit engineUnavailable(tr("Could not start %1: %2").arg(engine, m_process.errorString()));
        return;
    }
    request(QStringLiteral("hello"));
}

bool EngineClient::isReady() const
{
    return m_ready;
}

QString EngineClient::request(const QString &method, const QJsonObject &params)
{
    const QString id = QString::number(++m_nextId);
    m_methods.insert(id, method);
    QJsonObject message{{QStringLiteral("jsonrpc"), QStringLiteral("2.0")},
                        {QStringLiteral("id"), id},
                        {QStringLiteral("method"), method}};
    if (!params.isEmpty())
        message.insert(QStringLiteral("params"), params);
    sendObject(message);
    return id;
}

void EngineClient::cancel(const QString &requestId)
{
    request(QStringLiteral("cancel"), {{QStringLiteral("request_id"), requestId}});
}

QString EngineClient::locateEngine() const
{
    const QString configured = qEnvironmentVariable("WHODIS_GUI_ENGINE");
    if (!configured.isEmpty() && QFileInfo::exists(configured))
        return configured;

    const QDir appDirectory(QCoreApplication::applicationDirPath());
#ifdef Q_OS_WIN
    const QString executableName = QStringLiteral("whodis-gui-engine.exe");
#else
    const QString executableName = QStringLiteral("whodis-gui-engine");
#endif
    const QStringList candidates{
        appDirectory.filePath(executableName),
        appDirectory.filePath(QStringLiteral("../Helpers/") + executableName),
        appDirectory.filePath(QStringLiteral("../lib/whodis/") + executableName),
        appDirectory.filePath(QStringLiteral("../libexec/whodis/") + executableName),
        QStringLiteral("/usr/lib/whodis/") + executableName,
        QStringLiteral("/usr/libexec/whodis/") + executableName,
    };
    for (const QString &candidate : candidates) {
        if (QFileInfo(candidate).isExecutable())
            return QDir::cleanPath(candidate);
    }
    return QStandardPaths::findExecutable(executableName);
}

void EngineClient::readOutput()
{
    m_outputBuffer += m_process.readAllStandardOutput();
    qsizetype newline = -1;
    while ((newline = m_outputBuffer.indexOf('\n')) >= 0) {
        const QByteArray line = m_outputBuffer.left(newline).trimmed();
        m_outputBuffer.remove(0, newline + 1);
        if (!line.isEmpty())
            processLine(line);
    }
}

void EngineClient::readError()
{
    const QByteArray diagnostics = m_process.readAllStandardError().trimmed();
    if (!diagnostics.isEmpty())
        qWarning("whodis-gui-engine: %s", diagnostics.constData());
}

void EngineClient::processFinished(int exitCode, QProcess::ExitStatus status)
{
    m_ready = false;
    const QString message = status == QProcess::CrashExit
        ? tr("The Whodis engine crashed.")
        : tr("The Whodis engine exited with code %1.").arg(exitCode);
    const auto pending = m_methods;
    m_methods.clear();
    m_outputBuffer.clear();
    for (auto iterator = pending.constBegin(); iterator != pending.constEnd(); ++iterator)
        emit requestFailed(iterator.key(), iterator.value(), message);
    if (!m_restarted) {
        m_restarted = true;
        start();
        return;
    }
    emit engineUnavailable(message);
}

void EngineClient::processLine(const QByteArray &line)
{
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(line, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        emit engineUnavailable(tr("The Whodis engine returned invalid data."));
        return;
    }
    const QJsonObject message = document.object();
    if (message.value(QStringLiteral("method")).toString() == QStringLiteral("progress")) {
        emit progressReceived(message.value(QStringLiteral("params")).toObject());
        return;
    }
    const QString id = message.value(QStringLiteral("id")).toString();
    const QString method = m_methods.take(id);
    if (message.contains(QStringLiteral("error"))) {
        emit requestFailed(id, method,
                           message.value(QStringLiteral("error")).toObject().value(QStringLiteral("message")).toString());
        return;
    }
    const QJsonValue result = message.value(QStringLiteral("result"));
    if (method == QStringLiteral("hello")) {
        const QJsonObject hello = result.toObject();
        const int protocolVersion = hello.value(QStringLiteral("protocol_version")).toInt();
        if (protocolVersion != supportedProtocolVersion) {
            emit engineUnavailable(tr("GUI protocol %1 is incompatible with engine protocol %2.")
                                       .arg(supportedProtocolVersion).arg(protocolVersion));
            return;
        }
        m_ready = true;
        emit engineReady(hello.value(QStringLiteral("engine_version")).toString(), protocolVersion);
    }
    emit responseReceived(id, method, result);
}

void EngineClient::sendObject(const QJsonObject &message)
{
    if (m_process.state() != QProcess::Running) {
        emit engineUnavailable(tr("The Whodis engine is not running."));
        return;
    }
    m_process.write(QJsonDocument(message).toJson(QJsonDocument::Compact));
    m_process.write("\n");
}
