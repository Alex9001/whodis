#pragma once

#include <QProcessEnvironment>

class QUrl;
class QWidget;

namespace ExternalLinks {

QProcessEnvironment sanitizedHostEnvironment(QProcessEnvironment environment,
                                             const QString &appDir);
bool open(const QUrl &url, QWidget *parent = nullptr);

}
