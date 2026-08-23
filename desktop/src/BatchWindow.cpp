#include "BatchWindow.h"

#include "AdaptiveItemView.h"
#include "EngineClient.h"
#include "ResultWidget.h"

#include <QCloseEvent>
#include <QComboBox>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLabel>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QSaveFile>
#include <QSettings>
#include <QSpinBox>
#include <QSplitter>
#include <QStatusBar>
#include <QTableWidget>
#include <QToolBar>
#include <QVBoxLayout>

namespace {
constexpr int maximumDesktopBatchTargets = 1000;

QString eventDate(const QJsonObject &result, const QStringList &actions)
{
    const QJsonArray events = result.value(QStringLiteral("object")).toObject().value(QStringLiteral("events")).toArray();
    for (const QJsonValue &value : events) {
        const QJsonObject event = value.toObject();
        if (actions.contains(event.value(QStringLiteral("action")).toString(), Qt::CaseInsensitive))
            return event.value(QStringLiteral("date")).toString();
    }
    return {};
}

QString dnsRecordTypes(const QJsonArray &records)
{
    QStringList types;
    for (const QJsonValue &value : records) {
        const QString type = value.toObject().value(QStringLiteral("type")).toString().toUpper();
        if (!type.isEmpty() && !types.contains(type))
            types.append(type);
    }
    types.sort(Qt::CaseInsensitive);
    return types.join(QStringLiteral(", "));
}
}

BatchWindow::BatchWindow(EngineClient *engine, const QJsonObject &options, QWidget *parent)
    : QMainWindow(parent)
    , m_engine(engine)
    , m_targets(new QPlainTextEdit(this))
    , m_mode(new QComboBox(this))
    , m_workers(new QSpinBox(this))
    , m_start(new QPushButton(tr("Start"), this))
    , m_cancel(new QPushButton(tr("Cancel"), this))
    , m_retry(new QPushButton(tr("Retry Failed"), this))
    , m_export(new QPushButton(tr("Export…"), this))
    , m_progress(new QProgressBar(this))
    , m_table(new QTableWidget(this))
    , m_result(new ResultWidget(this))
    , m_options(options)
{
    setWindowTitle(tr("Whodis Batch Lookup"));
    setWindowIcon(QIcon(QStringLiteral(":/icons/whodis.png")));
    resize(1050, 720);
    m_targets->setPlaceholderText(tr("One domain, IP, ASN, or URL per line\nBlank lines and lines beginning with # are ignored."));
    m_targets->setMaximumHeight(140);
    m_mode->addItem(tr("Registration"), QStringLiteral("registration"));
    m_mode->addItem(tr("DNS Inventory"), QStringLiteral("dns.inventory"));
    m_mode->addItem(tr("DNS Compare"), QStringLiteral("dns.compare"));
    m_mode->addItem(tr("Diagnose"), QStringLiteral("diagnose"));
    m_mode->addItem(tr("Investigate"), QStringLiteral("investigate"));
    m_mode->setToolTip(tr("Every mode uses the same operation engine as the main window."));
    m_workers->setRange(1, 32);
    m_workers->setValue(4);
    m_workers->setToolTip(tr("Concurrent lookups"));

    auto *toolbar = addToolBar(tr("Batch actions"));
    toolbar->setMovable(false);
    auto *importAction = toolbar->addAction(tr("Import…"));
    toolbar->addWidget(new QLabel(tr(" Mode: "), this));
    toolbar->addWidget(m_mode);
    toolbar->addWidget(new QLabel(tr("  Jobs: "), this));
    toolbar->addWidget(m_workers);
    toolbar->addSeparator();
    toolbar->addWidget(m_start);
    toolbar->addWidget(m_cancel);
    toolbar->addWidget(m_retry);
    toolbar->addWidget(m_export);

    m_table->setColumnCount(8);
    m_table->setHorizontalHeaderLabels({tr("Target"), tr("State"), tr("Expiration"), tr("Registrar"), tr("DNS Records"), tr("Stack"), tr("Protocol"), tr("Error")});
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setSortingEnabled(true);
    m_table->setAlternatingRowColors(true);
    m_table->setObjectName(QStringLiteral("batchResultsTable"));
    AdaptiveItemView::configure(m_table, QStringLiteral("batch/layout-v1/results"), {4, 2, 3, 4, 2, 6, 2, 5});

    auto *splitter = new QSplitter(Qt::Vertical, this);
    auto *top = new QWidget(splitter);
    auto *topLayout = new QVBoxLayout(top);
    topLayout->setContentsMargins(0, 0, 0, 0);
    topLayout->addWidget(m_targets);
    topLayout->addWidget(m_progress);
    topLayout->addWidget(m_table);
    splitter->addWidget(top);
    splitter->addWidget(m_result);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);
    setCentralWidget(splitter);

    m_progress->setVisible(false);
    m_cancel->setVisible(false);
    m_retry->setEnabled(false);
    m_export->setEnabled(false);
    m_start->setEnabled(m_engine && m_engine->isReady());

    connect(importAction, &QAction::triggered, this, &BatchWindow::importTargets);
    connect(m_start, &QPushButton::clicked, this, &BatchWindow::startLookup);
    connect(m_cancel, &QPushButton::clicked, this, &BatchWindow::cancelLookup);
    connect(m_retry, &QPushButton::clicked, this, &BatchWindow::retryFailed);
    connect(m_export, &QPushButton::clicked, this, &BatchWindow::exportResults);
    connect(m_table, &QTableWidget::itemSelectionChanged, this, &BatchWindow::showSelectedResult);
    connect(m_engine, &EngineClient::engineReady, this, [this](const QString &version, int, const QJsonArray &) {
        statusBar()->showMessage(tr("Engine %1 ready").arg(version), 3000);
        m_start->setEnabled(true);
    });
    connect(m_engine, &EngineClient::engineUnavailable, this, [this](const QString &message) {
        statusBar()->showMessage(message);
        m_start->setEnabled(false);
    });
    connect(m_engine, &EngineClient::responseReceived, this, &BatchWindow::handleResponse);
    connect(m_engine, &EngineClient::requestFailed, this, &BatchWindow::handleFailure);
    connect(m_engine, &EngineClient::progressReceived, this, &BatchWindow::handleProgress);

    QSettings settings;
    restoreGeometry(settings.value(QStringLiteral("batch/geometry")).toByteArray());
}

void BatchWindow::closeEvent(QCloseEvent *event)
{
    if (!m_activeRequest.isEmpty())
        m_engine->cancel(m_activeRequest);
    QSettings settings;
    settings.setValue(QStringLiteral("batch/geometry"), saveGeometry());
    QMainWindow::closeEvent(event);
}

void BatchWindow::importTargets()
{
    const QString path = QFileDialog::getOpenFileName(this, tr("Import targets"), {}, tr("Text files (*.txt);;All files (*)"));
    if (path.isEmpty())
        return;
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox::warning(this, tr("Could not import"), file.errorString());
        return;
    }
    m_targets->setPlainText(QString::fromUtf8(file.readAll()));
}

QStringList BatchWindow::targetsFromEditor() const
{
    QStringList targets;
    const QStringList lines = m_targets->toPlainText().split('\n');
    for (const QString &line : lines) {
        const QString target = line.trimmed();
        if (!target.isEmpty() && !target.startsWith('#'))
            targets.append(target);
    }
    return targets;
}

void BatchWindow::startLookup()
{
    const QStringList targets = targetsFromEditor();
    if (targets.isEmpty()) {
        statusBar()->showMessage(tr("Add at least one target."), 5000);
        return;
    }
    beginLookup(targets);
}

void BatchWindow::beginLookup(const QStringList &targets)
{
    if (targets.size() > maximumDesktopBatchTargets) {
        statusBar()->showMessage(tr("Desktop batches support at most %1 targets. Use the CLI streaming formats for larger jobs.").arg(maximumDesktopBatchTargets), 7000);
        return;
    }
    m_cancelRequested = false;
    m_resultMode = m_mode->currentData().toString();
    m_items = QVector<QJsonObject>(targets.size());
    m_table->setSortingEnabled(false);
    m_table->setRowCount(targets.size());
    for (int row = 0; row < targets.size(); ++row) {
        auto *targetItem = new QTableWidgetItem(targets.at(row));
        targetItem->setData(Qt::UserRole, row);
        m_table->setItem(row, 0, targetItem);
        m_table->setItem(row, 1, new QTableWidgetItem(tr("Queued")));
        for (int column = 2; column < m_table->columnCount(); ++column)
            m_table->setItem(row, column, new QTableWidgetItem);
    }
    AdaptiveItemView::refresh(m_table);
    m_token.clear();
    m_result->clearResult();
    m_progress->setRange(0, targets.size());
    m_progress->setValue(0);
    QJsonArray targetArray;
    for (const QString &target : targets)
        targetArray.append(target);
    QJsonObject params = m_options;
    if (m_resultMode != QStringLiteral("investigate"))
        params.remove(QStringLiteral("investigation"));
    else if (params.value(QStringLiteral("timeout_ms")).toInt() == 15000)
        params.insert(QStringLiteral("timeout_ms"), 30000);
    params.insert(QStringLiteral("targets"), targetArray);
    params.insert(QStringLiteral("operation"), m_resultMode);
    params.insert(QStringLiteral("workers"), m_workers->value());
    m_activeRequest = m_engine->request(QStringLiteral("run"), params);
    setBusy(true);
    statusBar()->showMessage(tr("Running %1 for %2 targets…").arg(m_mode->currentText()).arg(targets.size()));
}

void BatchWindow::cancelLookup()
{
    if (!m_activeRequest.isEmpty()) {
        m_cancelRequested = true;
        m_engine->cancel(m_activeRequest);
        statusBar()->showMessage(tr("Canceling batch…"));
    }
}

void BatchWindow::retryFailed()
{
    QStringList failed;
    QVector<int> indexes;
    for (int index = 0; index < m_items.size(); ++index) {
        const QJsonObject item = m_items[index];
        if (!item.value(QStringLiteral("report")).toObject().value(QStringLiteral("errors")).toArray().isEmpty()) {
            failed.append(item.value(QStringLiteral("input")).toString());
            indexes.append(index);
        }
    }
    if (!failed.isEmpty())
        beginRetry(failed, indexes);
}

void BatchWindow::beginRetry(const QStringList &targets, const QVector<int> &indexes)
{
    if (m_token.isEmpty() || targets.isEmpty() || targets.size() != indexes.size())
        return;
    m_cancelRequested = false;
    m_table->setSortingEnabled(false);
    for (int index : indexes) {
        const int row = rowForIndex(index);
        if (row < 0)
            continue;
        m_table->item(row, 1)->setText(tr("Queued for retry"));
        m_table->item(row, 7)->setText({});
    }
    m_progress->setRange(0, targets.size());
    m_progress->setValue(0);
    QJsonArray targetArray;
    QJsonArray replaceIndexes;
    for (const QString &target : targets)
        targetArray.append(target);
    for (int index : indexes)
        replaceIndexes.append(index);
    QJsonObject params = m_options;
    if (m_resultMode != QStringLiteral("investigate"))
        params.remove(QStringLiteral("investigation"));
    else if (params.value(QStringLiteral("timeout_ms")).toInt() == 15000)
        params.insert(QStringLiteral("timeout_ms"), 30000);
    params.insert(QStringLiteral("targets"), targetArray);
    params.insert(QStringLiteral("operation"), m_resultMode);
    params.insert(QStringLiteral("workers"), m_workers->value());
    params.insert(QStringLiteral("base_token"), m_token);
    params.insert(QStringLiteral("replace_indices"), replaceIndexes);
    m_activeRequest = m_engine->request(QStringLiteral("run"), params);
    setBusy(true);
    statusBar()->showMessage(tr("Retrying %1 failed target(s)…").arg(targets.size()));
}

void BatchWindow::exportResults()
{
    if (m_token.isEmpty())
        return;
    const QString filters = tr("CSV table (*.csv);;Tab-separated text (*.tsv);;NDJSON (*.ndjson);;JSON (*.json)");
    QString selectedFilter;
    const QString path = QFileDialog::getSaveFileName(this, tr("Export batch results"), QStringLiteral("whodis-results.csv"), filters, &selectedFilter);
    if (path.isEmpty())
        return;
    QString format = QStringLiteral("csv");
    if (selectedFilter.contains(QStringLiteral("tsv"), Qt::CaseInsensitive) || path.endsWith(QStringLiteral(".tsv"), Qt::CaseInsensitive))
        format = QStringLiteral("tsv");
    else if (selectedFilter.contains(QStringLiteral("NDJSON"), Qt::CaseInsensitive) || path.endsWith(QStringLiteral(".ndjson"), Qt::CaseInsensitive))
        format = QStringLiteral("ndjson");
    else if (selectedFilter.contains(QStringLiteral("JSON"), Qt::CaseInsensitive) || path.endsWith(QStringLiteral(".json"), Qt::CaseInsensitive))
        format = QStringLiteral("json");
    m_exportPath = path;
    m_exportRequest = m_engine->request(QStringLiteral("export"), {{QStringLiteral("token"), m_token}, {QStringLiteral("format"), format}});
}

void BatchWindow::handleResponse(const QString &id, const QString &method, const QJsonValue &result)
{
    if (method == QStringLiteral("run") && id == m_activeRequest) {
        const QJsonObject response = result.toObject();
        m_token = response.value(QStringLiteral("token")).toString();
        const QJsonArray items = response.value(QStringLiteral("items")).toArray();
        m_items.resize(items.size());
        for (int index = 0; index < items.size(); ++index) {
            m_items[index] = items.at(index).toObject();
            updateRow(index, m_items[index]);
        }
        if (m_table->currentRow() < 0) {
            for (int index = 0; index < m_items.size(); ++index) {
                if (!m_items[index].value(QStringLiteral("report")).toObject().isEmpty()) {
                    m_table->selectRow(rowForIndex(index));
                    break;
                }
            }
        }
        finishLookup(response.value(QStringLiteral("canceled")).toBool() || m_cancelRequested);
        return;
    }
    if (method == QStringLiteral("export") && id == m_exportRequest) {
        QSaveFile file(m_exportPath);
        if (!file.open(QIODevice::WriteOnly) || file.write(result.toObject().value(QStringLiteral("content")).toString().toUtf8()) < 0 || !file.commit())
            QMessageBox::warning(this, tr("Could not export"), file.errorString());
        else
            statusBar()->showMessage(tr("Exported %1").arg(QFileInfo(m_exportPath).fileName()), 5000);
        m_exportRequest.clear();
        m_exportPath.clear();
    }
}

void BatchWindow::handleFailure(const QString &id, const QString &, const QString &message)
{
    if (id == m_activeRequest) {
        statusBar()->showMessage(message);
        finishLookup(m_cancelRequested);
    } else if (id == m_exportRequest) {
        QMessageBox::warning(this, tr("Could not export"), message);
        m_exportRequest.clear();
    }
}

void BatchWindow::handleProgress(const QJsonObject &progress)
{
    if (progress.value(QStringLiteral("request_id")).toString() != m_activeRequest)
        return;
    m_progress->setValue(progress.value(QStringLiteral("completed")).toInt());
}

void BatchWindow::updateRow(int index, const QJsonObject &item)
{
    const int row = rowForIndex(index);
    if (row < 0)
        return;
    const QJsonObject report = item.value(QStringLiteral("report")).toObject();
    const QJsonObject registration = report.value(QStringLiteral("registration")).toObject();
    const QJsonObject object = registration.value(QStringLiteral("object")).toObject();
    const QJsonObject route = registration.value(QStringLiteral("route")).toObject();
    QJsonObject dns = report.value(QStringLiteral("dns")).toObject();
    if (dns.isEmpty())
        dns = report.value(QStringLiteral("diagnosis")).toObject().value(QStringLiteral("dns")).toObject();
    QJsonArray dnsRecords = dns.value(QStringLiteral("inventory")).toObject().value(QStringLiteral("records")).toArray();
    const QJsonArray errors = report.value(QStringLiteral("errors")).toArray();
    const bool failed = !errors.isEmpty();
    m_table->item(row, 0)->setText(item.value(QStringLiteral("input")).toString());
    m_table->item(row, 1)->setText(failed ? tr("Failed") : tr("Complete"));
    m_table->item(row, 2)->setText(eventDate(registration, {QStringLiteral("expiration"), QStringLiteral("expiry"), QStringLiteral("expires")}));
    m_table->item(row, 3)->setText(object.value(QStringLiteral("registrar")).toString());
    if (!dns.isEmpty()) {
        m_table->item(row, 4)->setData(Qt::DisplayRole, dnsRecords.size());
        m_table->item(row, 4)->setToolTip(tr("Record types: %1").arg(dnsRecordTypes(dnsRecords)));
    } else {
        m_table->item(row, 4)->setText({});
        m_table->item(row, 4)->setToolTip({});
    }
    m_table->item(row, 5)->setText(report.value(QStringLiteral("investigation")).toObject().value(QStringLiteral("summary")).toString());
    m_table->item(row, 6)->setText(route.value(QStringLiteral("protocol")).toString().toUpper());
    QStringList errorMessages;
    for (const QJsonValue &value : errors)
        errorMessages.append(value.toObject().value(QStringLiteral("message")).toString());
    m_table->item(row, 7)->setText(errorMessages.join(QStringLiteral("; ")));
    AdaptiveItemView::refreshRow(m_table, row);
}

int BatchWindow::rowForIndex(int index) const
{
    for (int row = 0; row < m_table->rowCount(); ++row) {
        const QTableWidgetItem *target = m_table->item(row, 0);
        if (target && target->data(Qt::UserRole).toInt() == index)
            return row;
    }
    return -1;
}

void BatchWindow::finishLookup(bool canceled)
{
    m_activeRequest.clear();
    setBusy(false);
    int failures = 0;
    for (const QJsonObject &item : std::as_const(m_items)) {
        if (!item.value(QStringLiteral("report")).toObject().value(QStringLiteral("errors")).toArray().isEmpty())
            ++failures;
    }
    m_retry->setEnabled(failures > 0);
    m_export->setEnabled(!m_token.isEmpty());
    m_table->setSortingEnabled(true);
    AdaptiveItemView::refresh(m_table);
    statusBar()->showMessage(canceled ? tr("Batch canceled.") : tr("Batch complete: %1 failures.").arg(failures), 7000);
}

void BatchWindow::setBusy(bool busy)
{
    m_start->setVisible(!busy);
    m_cancel->setVisible(busy);
    m_progress->setVisible(busy);
    m_mode->setEnabled(!busy);
    m_workers->setEnabled(!busy);
    m_targets->setReadOnly(busy);
    if (busy) {
        m_retry->setEnabled(false);
        m_export->setEnabled(false);
    }
}

void BatchWindow::showSelectedResult()
{
    const int row = m_table->currentRow();
    const QTableWidgetItem *target = row >= 0 ? m_table->item(row, 0) : nullptr;
    const int index = target ? target->data(Qt::UserRole).toInt() : -1;
    if (index >= 0 && index < m_items.size() && !m_items[index].value(QStringLiteral("report")).toObject().isEmpty()) {
        m_result->setReportItem(m_items[index]);
        if (m_resultMode == QStringLiteral("dns.inventory"))
            m_result->showDNSTab();
    }
}
