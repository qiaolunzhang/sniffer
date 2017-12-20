#include "mainwindow.h"
#include "ui_mainwindow.h"



MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    mainTreeView = new ListTreeView();
    ui->treeView->setModel(mainTreeView->mainModel);

    model_dev = new QStringListModel(this);

    mdevice = new getdevice();

    mdevice->set_all_device();

    QStringList List;
    for (int i=0; i<mdevice->device_count; i++) {
        List << mdevice->device_all[i];
    }

    model_dev->setStringList(List);
    ui->comboBox->setModel(model_dev);
    //mainTreeView->addOneCaptureItem("1", "2", "3", "4", "5", "6");
    msniffer = new sniffer(mainTreeView);
    msniffer->start();
}


MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::on_btn_run_clicked()
{
}

void MainWindow::on_pushButton_2_clicked()
{

}

