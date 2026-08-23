#include "ExternalLinks.h"

#include <QCoreApplication>
#include <QDesktopServices>
#include <QDir>
#include <QFileInfo>
#include <QList>
#include <QMessageBox>
#include <QProcess>
#include <QStringList>
#include <QUrl>

namespace {

bool isInsideAppDir(const QString &path, const QString &appDir)
{
    if (path.isEmpty() || appDir.isEmpty())
        return false;
    const QString cleanPath = QDir::cleanPath(path);
    const QString cleanAppDir = QDir::cleanPath(appDir);
    return cleanPath == cleanAppDir || cleanPath.startsWith(cleanAppDir + QLatin1Char('/'));
}

void stripAppDirEntries(QProcessEnvironment &environment, const QString &name,
                        const QString &appDir, const QString &fallback = {})
{
    const QStringList entries = environment.value(name).split(QLatin1Char(':'), Qt::SkipEmptyParts);
    QStringList retained;
    for (const QString &entry : entries) {
        if (!isInsideAppDir(entry, appDir))
            retained.append(entry);
    }
    if (retained.isEmpty()) {
        if (fallback.isEmpty())
            environment.remove(name);
        else
            environment.insert(name, fallback);
        return;
    }
    environment.insert(name, retained.join(QLatin1Char(':')));
}

bool startLinuxHostBrowser(const QUrl &url)
{
#ifdef Q_OS_LINUX
    const QString appDir = qEnvironmentVariable("APPDIR");
    if (appDir.isEmpty() && qEnvironmentVariableIsEmpty("APPIMAGE"))
        return false;

    struct Opener {
        QString program;
        QStringList arguments;
    };
    const QList<Opener> openers{
        {QStringLiteral("/usr/bin/xdg-open"), {}},
        {QStringLiteral("/usr/local/bin/xdg-open"), {}},
        {QStringLiteral("/bin/xdg-open"), {}},
        {QStringLiteral("/usr/bin/gio"), {QStringLiteral("open")}},
        {QStringLiteral("/usr/local/bin/gio"), {QStringLiteral("open")}},
    };
    for (const Opener &opener : openers) {
        const QFileInfo executable(opener.program);
        if (!executable.isFile() || !executable.isExecutable())
            continue;
        QProcess process;
        process.setProgram(opener.program);
        process.setArguments(opener.arguments + QStringList{url.toString(QUrl::FullyEncoded)});
        process.setProcessEnvironment(
            ExternalLinks::sanitizedHostEnvironment(QProcessEnvironment::systemEnvironment(), appDir));
        process.setStandardOutputFile(QProcess::nullDevice());
        process.setStandardErrorFile(QProcess::nullDevice());
        if (process.startDetached())
            return true;
    }
#else
    Q_UNUSED(url);
#endif
    return false;
}

void showOpenFailure(const QUrl &url, QWidget *parent)
{
    QMessageBox message(QMessageBox::Warning,
                        QCoreApplication::translate("ExternalLinks", "Could not open link"),
                        QCoreApplication::translate(
                            "ExternalLinks",
                            "Whodis could not start the default web browser. Copy this address and open it manually:\n\n%1")
                            .arg(url.toString()),
                        QMessageBox::Ok, parent);
    message.setTextFormat(Qt::PlainText);
    message.setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
    message.exec();
}

}

namespace ExternalLinks {

QProcessEnvironment sanitizedHostEnvironment(QProcessEnvironment environment,
                                             const QString &appDir)
{
    for (const QString &name : {QStringLiteral("APPDIR"), QStringLiteral("APPIMAGE"),
                                QStringLiteral("ARGV0")})
        environment.remove(name);

    stripAppDirEntries(environment, QStringLiteral("PATH"), appDir,
                       QStringLiteral("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"));
    stripAppDirEntries(environment, QStringLiteral("LD_LIBRARY_PATH"), appDir);
    stripAppDirEntries(environment, QStringLiteral("XDG_DATA_DIRS"), appDir,
                       QStringLiteral("/usr/local/share:/usr/share"));
    for (const QString &name : {QStringLiteral("QT_PLUGIN_PATH"),
                                QStringLiteral("QT_QPA_PLATFORM_PLUGIN_PATH"),
                                QStringLiteral("QML2_IMPORT_PATH"),
                                QStringLiteral("QML_IMPORT_PATH"),
                                QStringLiteral("GIO_EXTRA_MODULES"),
                                QStringLiteral("GI_TYPELIB_PATH"),
                                QStringLiteral("GTK_PATH"),
                                QStringLiteral("GDK_PIXBUF_MODULEDIR")})
        stripAppDirEntries(environment, name, appDir);

    for (const QString &name : {QStringLiteral("GDK_PIXBUF_MODULE_FILE"),
                                QStringLiteral("LD_PRELOAD")}) {
        if (isInsideAppDir(environment.value(name), appDir))
            environment.remove(name);
    }
    return environment;
}

bool open(const QUrl &url, QWidget *parent)
{
    const bool valid = url.isValid() && url.scheme() == QStringLiteral("https")
        && !url.host().isEmpty() && url.userInfo().isEmpty();
    if (valid && (startLinuxHostBrowser(url) || QDesktopServices::openUrl(url)))
        return true;
    showOpenFailure(url, parent);
    return false;
}

}
