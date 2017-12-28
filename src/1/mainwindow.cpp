#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    /* packetinfo window */
    packetModel = new QStandardItemModel(0, 7, this);
    packetModel->setHorizontalHeaderItem(0, new QStandardItem("No"));
    packetModel->setHorizontalHeaderItem(1, new QStandardItem("Time"));
    packetModel->setHorizontalHeaderItem(2, new QStandardItem("Source"));
    packetModel->setHorizontalHeaderItem(3, new QStandardItem("Destination"));
    packetModel->setHorizontalHeaderItem(4, new QStandardItem("Pro"));
    packetModel->setHorizontalHeaderItem(5, new QStandardItem("Len"));
    packetModel->setHorizontalHeaderItem(6, new QStandardItem("Info"));

    ui->packetTableView->setModel(packetModel);

    ui->packetTableView->setColumnWidth(0,40);
    ui->packetTableView->setColumnWidth(1,180);
    ui->packetTableView->setColumnWidth(2,120);
    ui->packetTableView->setColumnWidth(3,120);
    ui->packetTableView->setColumnWidth(4,50);
    ui->packetTableView->setColumnWidth(5,50);
    ui->packetTableView->setColumnWidth(6,250);
    ui->packetTableView->verticalHeader()->setMaximumSectionSize(ui->packetTableView->verticalHeader()->fontMetrics().height() + 4);
    ui->packetTableView->verticalHeader()->setDefaultSectionSize(ui->packetTableView->verticalHeader()->fontMetrics().height() + 4);
    ui->packetTableView->verticalHeader()->hide();

    ui->packetTableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->packetTableView->setEditTriggers(QAbstractItemView::NoEditTriggers);

    /* packet details */
    packetdetails = new QStandardItemModel(this);
    ui->packetDetails->setModel(packetdetails);
    ui->packetDetails->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->packetDetails->setHeaderHidden(true);

    ui->packetDataview->setWordWrapMode(QTextOption::NoWrap);

    /* get all device */
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

    ui->btn_rtn->setEnabled(false);
}


MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_btn_run_clicked()
{
    std::string filter_exp_string = ui->lineEdit->text().toStdString();

    std::cout << "filter_exp_string" << filter_exp_string << std::endl;

    char *filter_exp;
    filter_exp = new char[filter_exp_string.size() + 1];
    std::copy(filter_exp_string.begin(), filter_exp_string.end(), filter_exp);
    filter_exp[filter_exp_string.size()] = '\0';


    QByteArray q = ui->comboBox->currentText().toLatin1();
    device = q.data();

    if(snifferthread==NULL){
        snifferthread = new SnifferThread(packetModel,device, filter_exp);
    }
    snifferthread->start();
}

void MainWindow::on_btn_stop_clicked()
{
    snifferthread->stopcapture();

}

void MainWindow::on_packetTableView_doubleClicked(const QModelIndex &index)
{
    if(ui->btn_rtn->isEnabled()){
        printf("ip fragments details\n");
    }
    else{
        int dataindex = packetModel->data(packetModel->index(index.row(), 0)).toInt();
        int size = packetModel->data(packetModel->index(index.row(), 5)).toInt();
        snifferthread->FillData(ui->packetDataview, dataindex-1, size);
        snifferthread->FillDetails(packetdetails,dataindex-1,size);
    }

}

void MainWindow::on_pushButton_clicked()
{
    snifferthread->IpDefragment();

    QStandardItemModel *ipModel = new QStandardItemModel(0, 6, this);
    ipModel->setHorizontalHeaderItem(0, new QStandardItem("No"));
    ipModel->setHorizontalHeaderItem(1, new QStandardItem("Source"));
    ipModel->setHorizontalHeaderItem(2, new QStandardItem("Destination"));
    ipModel->setHorizontalHeaderItem(3, new QStandardItem("Pro"));
    ipModel->setHorizontalHeaderItem(4, new QStandardItem("Len"));
    ipModel->setHorizontalHeaderItem(5, new QStandardItem("Info"));

    ui->packetTableView->setModel(ipModel);
    ui->packetDataview->clear();
    packetdetails->clear();

    int size = snifferthread->Ip_Vec_Size();
    if(size<1){
        printf("No ip fragments");
    }
    else{
        snifferthread->Fill_IP_Fragments(ipModel);
        }

    ui->btn_rtn->setEnabled(true);

}


void MainWindow::on_pushButton_3_clicked()
{
    //save_dialog = new Save_Dialog;
    //save_dialog->show();
    QString name = QInputDialog::getText(this, "Name", "Enter a name");

    if(name.isEmpty()) return;
    std::cout << name.toStdString() << std::endl;

    // data save index
    std::vector<int> data_save_index;
    // pass the index to sniffer
    //QModelIndexList indexes_save = ui->packetTableView->selectionModel()->selection().indexes();
    QModelIndexList indexes_save_rows = ui->packetTableView->selectionModel()->selectedRows(0);
    for (int i = 0; i < indexes_save_rows.count(); ++i) {
        //std::cout << "number of rows is" << indexes_save_rows.count() << std::endl;
        //std::cout << "the row number is" << indexes_save_rows.at(i).row() << std::endl;
        data_save_index.push_back(indexes_save_rows.at(i).row());
    }
    snifferthread->SaveSelectedPacket(name, data_save_index);
}

void MainWindow::on_btn_clear_clicked()
{
    snifferthread->stopcapture();
    snifferthread = NULL;
    delete snifferthread;
    snifferthread = NULL;
    delete packetModel;
    packetModel = new QStandardItemModel(0, 6, this);
    packetModel->setHorizontalHeaderItem(0, new QStandardItem("No"));
    packetModel->setHorizontalHeaderItem(1, new QStandardItem("Time"));
    packetModel->setHorizontalHeaderItem(2, new QStandardItem("Source"));
    packetModel->setHorizontalHeaderItem(3, new QStandardItem("Destination"));
    packetModel->setHorizontalHeaderItem(4, new QStandardItem("Pro"));
    packetModel->setHorizontalHeaderItem(5, new QStandardItem("Len"));
    packetModel->setHorizontalHeaderItem(6, new QStandardItem("Info"));

    ui->packetTableView->setModel(packetModel);
}

void MainWindow::on_btn_rtn_clicked()
{
    ui->packetTableView->setModel(packetModel);
    ui->btn_rtn->setEnabled(false);
}
