#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTreeWidget>
#include <QStandardItemModel>
#include <QtWidgets>
#include <QString>
#include <string>
#include "listtreeview.h"
#include "sniffer.h"
#include "snifferthread.h"
#include "protocol.h"

class ListTreeView;

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
private slots:
    void on_btn_run_clicked();
    void on_btn_stop_clicked();

private:
    Ui::MainWindow      *ui;
    sniffer             *msniffer;
    ListTreeView        *mainTreeView;
    QStringListModel    *model_dev;
    SnifferThread       *snifferthread;
    char                *device;
    void DoSelect(QString);
};

#endif // MAINWINDOW_H
