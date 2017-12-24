#ifndef SAVE_DIALOG_H
#define SAVE_DIALOG_H

#include <QDialog>
#include <QDirModel>
#include <QTreeView>
#include <QInputDialog>
#include <QFile>
#include <QTextStream>
#include <QFileSystemModel>

namespace Ui {
class Save_Dialog;
}

class Save_Dialog : public QDialog
{
    Q_OBJECT

public:
    explicit Save_Dialog(QWidget *parent = 0);
    ~Save_Dialog();

private slots:
    void on_pushButton_clicked();

private:
    Ui::Save_Dialog *ui;
    QDirModel *model;
};

#endif // SAVE_DIALOG_H
