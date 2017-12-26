#ifndef SAVE_DIALOG_H
#define SAVE_DIALOG_H

#include <QDialog>
#include <QDirModel>
#include <QTreeView>
#include <QInputDialog>
#include <QFile>
#include <QTextStream>
#include <QFileSystemModel>
#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> // for exit()
#include<string.h> //for memset


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
    void 					on_pushButton_clicked();

private:
    Ui::Save_Dialog 		*ui;
    QDirModel 				*model;
    FILE					*logfile;
};



#endif // SAVE_DIALOG_H
