#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTreeWidget>
#include <QStandardItemModel>
#include "listtreeview.h"

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

    void on_pushButton_2_clicked();

private:
    Ui::MainWindow *ui;
    ListTreeView *mainTreeView;
};

#endif // MAINWINDOW_H
