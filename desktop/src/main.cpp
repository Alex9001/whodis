#include "MainWindow.h"

#include <QApplication>
#include <QCoreApplication>
#include <QIcon>

int main(int argc, char *argv[])
{
    QApplication application(argc, argv);
    QCoreApplication::setOrganizationName(QStringLiteral("Cyberbrand"));
    QCoreApplication::setOrganizationDomain(QStringLiteral("cyberbrand.net"));
    QCoreApplication::setApplicationName(QStringLiteral("Whodis"));
    QCoreApplication::setApplicationVersion(QStringLiteral(WHODIS_GUI_VERSION));
    application.setWindowIcon(QIcon(QStringLiteral(":/icons/whodis.png")));

    MainWindow window;
    window.show();
    return application.exec();
}

