#pragma once

#include <QList>
#include <QString>

class QTableWidget;
class QTreeWidget;

namespace AdaptiveItemView {

void configure(QTableWidget *table, const QString &settingsKey, const QList<int> &widthWeights);
void configure(QTreeWidget *tree, const QString &settingsKey, const QList<int> &widthWeights);
void refresh(QTableWidget *table);
void refresh(QTreeWidget *tree);
void refreshRow(QTableWidget *table, int row);

}
