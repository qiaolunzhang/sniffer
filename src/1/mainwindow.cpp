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

    msniffer = new sniffer();

    msniffer->set_all_device();

    QStringList List;
    for (int i=0; i<msniffer->device_count; i++) {
        List << msniffer->device_all[i];
    }

    model_dev->setStringList(List);
    ui->comboBox->setModel(model_dev);
    mainTreeView->addOneCaptureItem("1", "2", "3", "4", "5", "6");
    printf("start");
}


MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_btn_run_clicked()
{
    QByteArray q = ui->comboBox->currentText().toLatin1();
    device = q.data();
    if(snifferthread==NULL)snifferthread = new SnifferThread(mainTreeView,device);

    snifferthread->start();
}



void MainWindow::on_btn_stop_clicked()
{
    snifferthread->stopcapture();
}
