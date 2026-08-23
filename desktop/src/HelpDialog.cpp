#include "HelpDialog.h"

#include "ExternalLinks.h"

#include <QCloseEvent>
#include <QDialogButtonBox>
#include <QFile>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QKeySequence>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPushButton>
#include <QSettings>
#include <QShortcut>
#include <QSplitter>
#include <QTextBrowser>
#include <QUrl>
#include <QVBoxLayout>

HelpDialog::HelpDialog(QWidget *parent)
    : QDialog(parent)
    , m_search(new QLineEdit(this))
    , m_topics(new QListWidget(this))
    , m_content(new QTextBrowser(this))
{
    setWindowTitle(tr("Whodis Help"));
    setWindowIcon(QIcon(QStringLiteral(":/icons/whodis.png")));
    setModal(false);
    resize(860, 620);

    m_search->setPlaceholderText(tr("Search help topics"));
    m_search->setClearButtonEnabled(true);
    m_search->setAccessibleName(tr("Search Whodis help"));
    m_search->setObjectName(QStringLiteral("helpSearch"));
    m_topics->setAccessibleName(tr("Help topics"));
    m_topics->setObjectName(QStringLiteral("helpTopics"));
    m_content->setAccessibleName(tr("Help topic content"));
    m_content->setObjectName(QStringLiteral("helpContent"));
    m_content->setOpenExternalLinks(false);
    m_content->setReadOnly(true);

    auto *searchRow = new QHBoxLayout;
    auto *searchLabel = new QLabel(tr("Search:"), this);
    searchLabel->setBuddy(m_search);
    searchRow->addWidget(searchLabel);
    searchRow->addWidget(m_search, 1);

    auto *splitter = new QSplitter(this);
    splitter->addWidget(m_topics);
    splitter->addWidget(m_content);
    splitter->setStretchFactor(0, 1);
    splitter->setStretchFactor(1, 3);
    splitter->setSizes({220, 640});

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::close);
    connect(buttons->button(QDialogButtonBox::Close), &QPushButton::clicked, this, &QDialog::close);

    auto *layout = new QVBoxLayout(this);
    layout->addLayout(searchRow);
    layout->addWidget(splitter, 1);
    layout->addWidget(buttons);

    loadTopics();
    connect(m_search, &QLineEdit::textChanged, this, &HelpDialog::filterTopics);
    connect(m_topics, &QListWidget::currentRowChanged, this, &HelpDialog::showSelectedTopic);
    connect(m_content, &QTextBrowser::anchorClicked, this, &HelpDialog::openLink);
    auto *findShortcut = new QShortcut(QKeySequence::Find, this);
    connect(findShortcut, &QShortcut::activated, m_search, qOverload<>(&QWidget::setFocus));

    QSettings settings;
    restoreGeometry(settings.value(QStringLiteral("help/geometry")).toByteArray());
    restoreSelection();
}

int HelpDialog::topicCount() const
{
    return m_catalog.size();
}

QString HelpDialog::currentTitle() const
{
    const int row = m_topics->currentRow();
    if (row < 0 || row >= m_catalog.size())
        return {};
    return m_catalog.at(row).title;
}

void HelpDialog::setSearchText(const QString &text)
{
    m_search->setText(text);
}

void HelpDialog::closeEvent(QCloseEvent *event)
{
    QSettings settings;
    settings.setValue(QStringLiteral("help/geometry"), saveGeometry());
    if (const int row = m_topics->currentRow(); row >= 0 && row < m_catalog.size())
        settings.setValue(QStringLiteral("help/topic"), m_catalog.at(row).id);
    QDialog::closeEvent(event);
}

void HelpDialog::loadTopics()
{
    QFile catalogFile(QStringLiteral(":/help/catalog.json"));
    if (!catalogFile.open(QIODevice::ReadOnly)) {
        m_content->setPlainText(tr("The bundled help catalog could not be opened."));
        return;
    }
    const QJsonDocument document = QJsonDocument::fromJson(catalogFile.readAll());
    const QJsonArray topics = document.object().value(QStringLiteral("topics")).toArray();
    for (const QJsonValue &value : topics) {
        const QJsonObject object = value.toObject();
        QFile bodyFile(QStringLiteral(":/help/") + object.value(QStringLiteral("file")).toString());
        if (!bodyFile.open(QIODevice::ReadOnly))
            continue;
        Topic topic{object.value(QStringLiteral("id")).toString(),
                    object.value(QStringLiteral("title")).toString(),
                    object.value(QStringLiteral("summary")).toString(),
                    QString::fromUtf8(bodyFile.readAll())};
        if (topic.id.isEmpty() || topic.title.isEmpty() || topic.body.isEmpty())
            continue;
        m_catalog.append(topic);
        auto *item = new QListWidgetItem(topic.title, m_topics);
        item->setToolTip(topic.summary);
    }
}

void HelpDialog::restoreSelection()
{
    const QString wanted = QSettings().value(QStringLiteral("help/topic"), QStringLiteral("overview")).toString();
    int row = 0;
    for (int index = 0; index < m_catalog.size(); ++index) {
        if (m_catalog.at(index).id == wanted) {
            row = index;
            break;
        }
    }
    if (!m_catalog.isEmpty())
        m_topics->setCurrentRow(row);
}

void HelpDialog::filterTopics(const QString &text)
{
    const QString needle = text.trimmed();
    int firstVisible = -1;
    for (int index = 0; index < m_catalog.size(); ++index) {
        const Topic &topic = m_catalog.at(index);
        const bool visible = needle.isEmpty()
            || topic.title.contains(needle, Qt::CaseInsensitive)
            || topic.summary.contains(needle, Qt::CaseInsensitive)
            || topic.body.contains(needle, Qt::CaseInsensitive);
        m_topics->item(index)->setHidden(!visible);
        if (visible && firstVisible < 0)
            firstVisible = index;
    }
    if (firstVisible >= 0 && (m_topics->currentItem() == nullptr || m_topics->currentItem()->isHidden()))
        m_topics->setCurrentRow(firstVisible);
    if (firstVisible < 0)
        m_content->setPlainText(tr("No help topics match “%1”.").arg(needle));
}

void HelpDialog::showSelectedTopic()
{
    const int row = m_topics->currentRow();
    if (row < 0 || row >= m_catalog.size() || m_topics->item(row)->isHidden())
        return;
    m_content->document()->setBaseUrl(QUrl(QStringLiteral("qrc:/help/")));
    m_content->setMarkdown(m_catalog.at(row).body);
}

void HelpDialog::openLink(const QUrl &url)
{
    if (url.scheme() == QStringLiteral("https"))
        ExternalLinks::open(url, this);
}
