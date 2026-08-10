#include "MainWindow.h"

#include "AdvancedDialog.h"
#include "BatchWindow.h"
#include "EngineClient.h"
#include "ResultWidget.h"

#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QCloseEvent>
#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLabel>
#include <QLineEdit>
#include <QMenuBar>
#include <QMessageBox>
#include <QProgressBar>
#include <QPushButton>
#include <QSaveFile>
#include <QSettings>
#include <QStatusBar>
#include <QTimer>
#include <QToolBar>
#include <QVBoxLayout>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , m_engine(new EngineClient(this))
    , m_advanced(new AdvancedDialog(this))
    , m_target(new QLineEdit(this))
    , m_lookup(new QPushButton(tr("Lookup"), this))
    , m_scan(new QPushButton(tr("Scan DNS"), this))
    , m_batch(new QPushButton(tr("Batch…"), this))
    , m_cancel(new QPushButton(tr("Cancel"), this))
    , m_progress(new QProgressBar(this))
    , m_result(new ResultWidget(this))
    , m_validationTimer(new QTimer(this))
{
    setWindowTitle(tr("Whodis"));
    setWindowIcon(QIcon(QStringLiteral(":/icons/whodis.png")));
    resize(900, 640);
    m_target->setPlaceholderText(tr("Domain, IP, ASN, or URL"));
    m_target->setClearButtonEnabled(true);
    m_lookup->setDefault(true);
    m_progress->setRange(0, 0);
    m_progress->setMaximumWidth(150);
    m_progress->setVisible(false);
    m_cancel->setVisible(false);
    m_validationTimer->setSingleShot(true);
    m_validationTimer->setInterval(250);

    auto *queryLayout = new QHBoxLayout;
    queryLayout->addWidget(m_target, 1);
    queryLayout->addWidget(m_lookup);
    queryLayout->addWidget(m_scan);
    queryLayout->addWidget(m_batch);
    queryLayout->addWidget(m_cancel);
    queryLayout->addWidget(m_progress);
    auto *central = new QWidget(this);
    auto *centralLayout = new QVBoxLayout(central);
    centralLayout->addLayout(queryLayout);
    centralLayout->addWidget(m_result, 1);
    setCentralWidget(central);

    auto *fileMenu = menuBar()->addMenu(tr("&File"));
    auto *batchAction = fileMenu->addAction(tr("&Batch Lookup…"));
    batchAction->setShortcut(QKeySequence(QStringLiteral("Ctrl+B")));
    connect(batchAction, &QAction::triggered, this, &MainWindow::openBatch);
    m_saveAction = fileMenu->addAction(tr("&Save Result…"));
    m_saveAction->setShortcut(QKeySequence::Save);
    connect(m_saveAction, &QAction::triggered, this, &MainWindow::saveCurrent);
    fileMenu->addSeparator();
    auto *exitAction = fileMenu->addAction(tr("E&xit"));
    exitAction->setShortcut(QKeySequence::Quit);
    connect(exitAction, &QAction::triggered, this, &QWidget::close);
    auto *editMenu = menuBar()->addMenu(tr("&Edit"));
    m_copyAction = editMenu->addAction(tr("&Copy Current View"));
    m_copyAction->setShortcut(QKeySequence::Copy);
    connect(m_copyAction, &QAction::triggered, this, &MainWindow::copyCurrent);
    auto *toolsMenu = menuBar()->addMenu(tr("&Tools"));
    m_axfrAction = toolsMenu->addAction(tr("Authoritative Zone Transfer…"), this, &MainWindow::runAXFR);
    toolsMenu->addAction(tr("Advanced Lookup Options…"), this, &MainWindow::openAdvanced);
    auto *helpMenu = menuBar()->addMenu(tr("&Help"));
    helpMenu->addAction(tr("About Whodis"), this, [this] {
        QMessageBox::about(this, tr("About Whodis"),
                           tr("Whodis %1\n\nA modern WHOIS alternative using RDAP, WHOIS, RWhois, and public DNS.\n\nHomepage: https://cyberbrand.net/whodis/\nSource and releases: https://github.com/Alex9001/whodis\n\nMIT © 2026 Aleksandr Oreshkin")
                               .arg(QStringLiteral(WHODIS_GUI_VERSION)));
    });

    auto *toolbar = addToolBar(tr("Actions"));
    toolbar->setMovable(false);
    toolbar->addAction(m_saveAction);
    toolbar->addAction(m_copyAction);
    toolbar->addSeparator();
    toolbar->addAction(tr("Advanced…"), this, &MainWindow::openAdvanced);

    connect(m_target, &QLineEdit::textChanged, this, &MainWindow::scheduleValidation);
    connect(m_target, &QLineEdit::returnPressed, this, &MainWindow::runLookup);
    connect(m_validationTimer, &QTimer::timeout, this, &MainWindow::validateTarget);
    connect(m_lookup, &QPushButton::clicked, this, &MainWindow::runLookup);
    connect(m_scan, &QPushButton::clicked, this, &MainWindow::runDNSScan);
    connect(m_batch, &QPushButton::clicked, this, &MainWindow::openBatch);
    connect(m_cancel, &QPushButton::clicked, this, &MainWindow::cancelLookup);
    connect(m_engine, &EngineClient::engineReady, this, [this](const QString &version, int) {
        statusBar()->showMessage(tr("Engine %1 ready").arg(version), 3000);
        scheduleValidation();
        updateActionState();
    });
    connect(m_engine, &EngineClient::engineUnavailable, this, [this](const QString &message) {
        statusBar()->showMessage(message);
        updateActionState();
    });
    connect(m_engine, &EngineClient::responseReceived, this, &MainWindow::handleResponse);
    connect(m_engine, &EngineClient::requestFailed, this, &MainWindow::handleFailure);
    connect(m_engine, &EngineClient::progressReceived, this, &MainWindow::handleProgress);

    QSettings settings;
    restoreGeometry(settings.value(QStringLiteral("main/geometry")).toByteArray());
    m_engine->start();
    updateActionState();
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    if (!m_lookupRequest.isEmpty())
        m_engine->cancel(m_lookupRequest);
    QSettings settings;
    settings.setValue(QStringLiteral("main/geometry"), saveGeometry());
    QMainWindow::closeEvent(event);
}

void MainWindow::scheduleValidation()
{
    m_validKind.clear();
    m_validationTimer->start();
    updateActionState();
}

void MainWindow::validateTarget()
{
    if (!m_engine->isReady() || m_target->text().trimmed().isEmpty())
        return;
    m_parseRequest = m_engine->request(QStringLiteral("parse"), {{QStringLiteral("input"), m_target->text().trimmed()}});
}

void MainWindow::runLookup()
{
    startLookup(QStringLiteral("registration"));
}

void MainWindow::runDNSScan()
{
    startLookup(QStringLiteral("scan"));
}

void MainWindow::runAXFR()
{
    if (m_validKind != QStringLiteral("domain"))
        return;
    if (QMessageBox::question(this, tr("Attempt zone transfer"),
                              tr("Whodis will ask the authoritative nameservers for a complete zone transfer. Most public zones correctly refuse this. Continue?")) == QMessageBox::Yes)
        startLookup(QStringLiteral("axfr"));
}

void MainWindow::startLookup(const QString &mode)
{
    const QString target = m_target->text().trimmed();
    if (!m_engine->isReady() || target.isEmpty() || !m_lookupRequest.isEmpty())
        return;
    QJsonObject params = m_advanced->options();
    params.insert(QStringLiteral("targets"), QJsonArray{target});
    params.insert(QStringLiteral("mode"), mode);
    m_lookupRequest = m_engine->request(QStringLiteral("lookup"), params);
    m_resultToken.clear();
    setBusy(true);
    statusBar()->showMessage(mode == QStringLiteral("scan") ? tr("Looking up registration and DNS…") : tr("Looking up registration…"));
}

void MainWindow::cancelLookup()
{
    if (!m_lookupRequest.isEmpty())
        m_engine->cancel(m_lookupRequest);
}

void MainWindow::openBatch()
{
    auto *window = new BatchWindow(this);
    window->setAttribute(Qt::WA_DeleteOnClose);
    window->show();
    window->raise();
}

void MainWindow::openAdvanced()
{
    const QJsonObject previous = m_advanced->options();
    if (m_advanced->exec() != QDialog::Accepted)
        m_advanced->setOptions(previous);
}

void MainWindow::copyCurrent()
{
    const QString text = m_result->copyText();
    if (!text.isEmpty()) {
        QApplication::clipboard()->setText(text);
        statusBar()->showMessage(tr("Copied current result."), 3000);
    }
}

void MainWindow::saveCurrent()
{
    if (m_resultToken.isEmpty())
        return;
    const QString filters = tr("JSON (*.json);;Plain text (*.txt);;Raw response (*.raw.txt)");
    QString selectedFilter;
    const QString path = QFileDialog::getSaveFileName(this, tr("Save Whodis result"), m_result->currentTarget() + QStringLiteral(".json"), filters, &selectedFilter);
    if (path.isEmpty())
        return;
    QString format = QStringLiteral("json");
    if (selectedFilter.contains(QStringLiteral("Plain"), Qt::CaseInsensitive) || path.endsWith(QStringLiteral(".txt"), Qt::CaseInsensitive))
        format = QStringLiteral("plain");
    if (selectedFilter.contains(QStringLiteral("Raw"), Qt::CaseInsensitive) || path.endsWith(QStringLiteral(".raw.txt"), Qt::CaseInsensitive))
        format = QStringLiteral("raw");
    m_exportPath = path;
    m_exportRequest = m_engine->request(QStringLiteral("export"), {{QStringLiteral("token"), m_resultToken}, {QStringLiteral("format"), format}});
}

void MainWindow::handleResponse(const QString &id, const QString &method, const QJsonValue &result)
{
    if (method == QStringLiteral("parse") && id == m_parseRequest) {
        const QJsonObject parsed = result.toObject();
        m_validKind = parsed.value(QStringLiteral("target")).toObject().value(QStringLiteral("kind")).toString();
        const QString normalized = parsed.value(QStringLiteral("normalized")).toString();
        m_target->setToolTip(normalized == m_target->text().trimmed() ? QString() : tr("Will look up %1").arg(normalized));
        statusBar()->clearMessage();
        updateActionState();
        return;
    }
    if (method == QStringLiteral("lookup") && id == m_lookupRequest) {
        const QJsonObject lookup = result.toObject();
        m_resultToken = lookup.value(QStringLiteral("token")).toString();
        const QJsonArray items = lookup.value(QStringLiteral("items")).toArray();
        if (items.isEmpty()) {
            m_lookupRequest.clear();
            setBusy(false);
            statusBar()->showMessage(tr("The engine returned no result."));
            return;
        }
        const QJsonObject item = items.at(0).toObject();
        const QJsonObject error = item.value(QStringLiteral("error")).toObject();
        if (!error.isEmpty()) {
            statusBar()->showMessage(error.value(QStringLiteral("message")).toString());
        } else {
            m_result->setItem(item);
            statusBar()->showMessage(tr("Lookup complete."), 5000);
        }
        m_lookupRequest.clear();
        setBusy(false);
        return;
    }
    if (method == QStringLiteral("export") && id == m_exportRequest) {
        QSaveFile file(m_exportPath);
        if (!file.open(QIODevice::WriteOnly) || file.write(result.toObject().value(QStringLiteral("content")).toString().toUtf8()) < 0 || !file.commit())
            QMessageBox::warning(this, tr("Could not save"), file.errorString());
        else
            statusBar()->showMessage(tr("Saved %1").arg(QFileInfo(m_exportPath).fileName()), 5000);
        m_exportRequest.clear();
        m_exportPath.clear();
    }
}

void MainWindow::handleFailure(const QString &id, const QString &method, const QString &message)
{
    if (method == QStringLiteral("parse") && id == m_parseRequest) {
        m_validKind.clear();
        m_target->setToolTip(message);
        statusBar()->showMessage(message);
        updateActionState();
        return;
    }
    if (id == m_lookupRequest) {
        m_lookupRequest.clear();
        setBusy(false);
        statusBar()->showMessage(message);
    } else if (id == m_exportRequest) {
        m_exportRequest.clear();
        QMessageBox::warning(this, tr("Could not save"), message);
    }
}

void MainWindow::handleProgress(const QJsonObject &progress)
{
    if (progress.value(QStringLiteral("request_id")).toString() == m_lookupRequest)
        statusBar()->showMessage(tr("Lookup complete; preparing result…"));
}

void MainWindow::setBusy(bool busy)
{
    m_target->setReadOnly(busy);
    m_lookup->setVisible(!busy);
    m_scan->setVisible(!busy);
    m_batch->setEnabled(!busy);
    m_cancel->setVisible(busy);
    m_progress->setVisible(busy);
    updateActionState();
}

void MainWindow::updateActionState()
{
    const bool idle = m_lookupRequest.isEmpty();
    const bool valid = !m_validKind.isEmpty();
    m_lookup->setEnabled(m_engine->isReady() && idle && valid);
    m_scan->setEnabled(m_engine->isReady() && idle && m_validKind == QStringLiteral("domain"));
    m_axfrAction->setEnabled(m_engine->isReady() && idle && m_validKind == QStringLiteral("domain"));
    m_saveAction->setEnabled(!m_resultToken.isEmpty());
    m_copyAction->setEnabled(!m_result->currentTarget().isEmpty());
}
