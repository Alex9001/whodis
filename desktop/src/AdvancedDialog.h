#pragma once

#include <QDialog>
#include <QJsonObject>

class QCheckBox;
class QComboBox;
class QDialogButtonBox;
class QLineEdit;
class QSpinBox;

class AdvancedDialog final : public QDialog
{
    Q_OBJECT

public:
    explicit AdvancedDialog(QWidget *parent = nullptr);
    QJsonObject options() const;
    void setOptions(const QJsonObject &options);

private slots:
    void updateState();

private:
    QComboBox *m_protocol;
    QComboBox *m_fallback;
    QLineEdit *m_server;
    QLineEdit *m_resolver;
    QSpinBox *m_timeout;
    QCheckBox *m_refresh;
    QDialogButtonBox *m_buttons;
};
