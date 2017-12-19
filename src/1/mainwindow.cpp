#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    packetModel = new QStandardItemModel(0, 7, this);
    packetModel->setHorizontalHeaderItem(0, new QStandardItem("#"));
    packetModel->setHorizontalHeaderItem(1, new QStandardItem("Time"));
    packetModel->setHorizontalHeaderItem(2, new QStandardItem("Src"));
    packetModel->setHorizontalHeaderItem(3, new QStandardItem("Dest"));
    packetModel->setHorizontalHeaderItem(4, new QStandardItem("Size"));
    packetModel->setHorizontalHeaderItem(5, new QStandardItem("Pro"));
    packetModel->setHorizontalHeaderItem(6, new QStandardItem("Info"));

    packetModelProxy = new QSortFilterProxyModel(this);
    packetModelProxy->setSourceModel(packetModel);

    ui->packetTableView->setModel(packetModelProxy);
    ui->packetTableView->resizeColumnsToContents();

    ui->packetTableView->verticalHeader()->setMaximumSectionSize(ui->packetTableView->verticalHeader()->fontMetrics().height() + 4);
    ui->packetTableView->verticalHeader()->setDefaultSectionSize(ui->packetTableView->verticalHeader()->fontMetrics().height() + 4);
    ui->packetTableView->verticalHeader()->hide();

    //ui->packetTableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->packetTableView->setEditTriggers(QAbstractItemView::NoEditTriggers);

//get all device
    model_dev = new QStringListModel(this);
    msniffer = new sniffer();
    msniffer->set_all_device();
    QStringList List;
    for (int i=0; i<msniffer->device_count; i++) {
        List << msniffer->device_all[i];
    }
    model_dev->setStringList(List);
    ui->comboBox->setModel(model_dev);
    snifferthread = NULL;
}


MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_btn_run_clicked()
{
    printf("start\n");
    QByteArray q = ui->comboBox->currentText().toLatin1();
    device = q.data();
    if(snifferthread==NULL){
        snifferthread = new SnifferThread(packetModel,device);
    }
    printf("thread ok\n");
    snifferthread->start();
}



void MainWindow::on_btn_stop_clicked()
{
    snifferthread->stopcapture();
}
