#include "AdaptiveItemView.h"

#include <QAbstractItemView>
#include <QFontMetrics>
#include <QHeaderView>
#include <QSettings>
#include <QStyledItemDelegate>
#include <QStyleOptionViewItem>
#include <QTableWidget>
#include <QTimer>
#include <QTreeWidget>

namespace {

class WrappingItemDelegate final : public QStyledItemDelegate
{
public:
    explicit WrappingItemDelegate(QObject *parent)
        : QStyledItemDelegate(parent)
    {
    }

    void initStyleOption(QStyleOptionViewItem *option, const QModelIndex &index) const override
    {
        QStyledItemDelegate::initStyleOption(option, index);
        option->features |= QStyleOptionViewItem::WrapText;
        option->textElideMode = Qt::ElideNone;
    }

    QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const override
    {
        QStyleOptionViewItem wrapped(option);
        initStyleOption(&wrapped, index);
        QSize size = QStyledItemDelegate::sizeHint(wrapped, index);

        int width = wrapped.rect.width();
        if (width <= 0) {
            if (const auto *table = qobject_cast<const QTableWidget *>(wrapped.widget))
                width = table->horizontalHeader()->sectionSize(index.column());
            else if (const auto *tree = qobject_cast<const QTreeWidget *>(wrapped.widget))
                width = tree->header()->sectionSize(index.column());
        }
        const int textWidth = qMax(24, width - 14);
        const QRect bounds = wrapped.fontMetrics.boundingRect(
            QRect(0, 0, textWidth, 100000), Qt::TextWordWrap | Qt::AlignLeft | Qt::AlignVCenter, wrapped.text);
        size.setHeight(qMax(size.height(), bounds.height() + 8));
        return size;
    }
};

QString stateKey(const QString &settingsKey)
{
    return settingsKey + QStringLiteral("/state");
}

QString countKey(const QString &settingsKey)
{
    return settingsKey + QStringLiteral("/columns");
}

void applyDefaultWidths(QHeaderView *header, int availableWidth, const QList<int> &weights)
{
    if (!header || header->count() == 0 || weights.size() != header->count())
        return;
    int totalWeight = 0;
    for (const int weight : weights)
        totalWeight += qMax(1, weight);
    availableWidth = qMax(availableWidth, header->minimumSectionSize() * header->count());
    for (int column = 0; column < header->count(); ++column)
        header->resizeSection(column, qMax(header->minimumSectionSize(), availableWidth * qMax(1, weights.at(column)) / totalWeight));
}

template <typename View, typename Refresh>
void configureView(View *view, QHeaderView *header, const QString &settingsKey,
                   const QList<int> &widthWeights, Refresh refresh)
{
    view->setWordWrap(true);
    view->setTextElideMode(Qt::ElideNone);
    view->setItemDelegate(new WrappingItemDelegate(view));
    header->setSectionsMovable(false);
    header->setMinimumSectionSize(56);
    header->setStretchLastSection(false);
    header->setSectionResizeMode(QHeaderView::Interactive);

    QSettings settings;
    const bool restored = settings.value(countKey(settingsKey)).toInt() == header->count()
        && header->restoreState(settings.value(stateKey(settingsKey)).toByteArray());
    if (!restored) {
        QTimer::singleShot(0, view, [view, header, widthWeights] {
            applyDefaultWidths(header, qMax(view->viewport()->width(), 720), widthWeights);
        });
    }

    auto *resizeTimer = new QTimer(view);
    resizeTimer->setSingleShot(true);
    resizeTimer->setInterval(75);
    QObject::connect(resizeTimer, &QTimer::timeout, view, [header, settingsKey, refresh] {
        QSettings settings;
        settings.setValue(countKey(settingsKey), header->count());
        settings.setValue(stateKey(settingsKey), header->saveState());
        refresh();
    });
    QObject::connect(header, &QHeaderView::sectionResized, resizeTimer,
                     [resizeTimer](int, int, int) { resizeTimer->start(); });
}

} // namespace

namespace AdaptiveItemView {

void configure(QTableWidget *table, const QString &settingsKey, const QList<int> &widthWeights)
{
    table->verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    configureView(table, table->horizontalHeader(), settingsKey, widthWeights,
                  [table] { refresh(table); });
}

void configure(QTreeWidget *tree, const QString &settingsKey, const QList<int> &widthWeights)
{
    tree->setUniformRowHeights(false);
    configureView(tree, tree->header(), settingsKey, widthWeights,
                  [tree] { refresh(tree); });
}

void refresh(QTableWidget *table)
{
    if (table)
        table->resizeRowsToContents();
}

void refresh(QTreeWidget *tree)
{
    if (tree)
        tree->doItemsLayout();
}

void refreshRow(QTableWidget *table, int row)
{
    if (table && row >= 0 && row < table->rowCount())
        table->resizeRowToContents(row);
}

} // namespace AdaptiveItemView
