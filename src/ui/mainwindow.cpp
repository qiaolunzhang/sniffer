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
    //msniffer = new sniffer();
    //msniffer->start();
}


MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::on_btn_run_clicked()
{
    //ui->label_2->setText(ui->lineEdit->text());
    std::string device_string = ui->comboBox->currentText().toStdString();
    char *device = new char[device_string.size() + 1];
    std::copy(device_string.begin(), device_string.end(), device);

    std::string filter_exp_string = ui->lineEdit->text().toStdString();

    std::cout << "filter_exp_string" << filter_exp_string << std::endl;
    //std::cout << "length" << strlen(filter_exp_string);

    char *filter_exp;
    filter_exp = new char[filter_exp_string.size() + 1];
    std::copy(filter_exp_string.begin(), filter_exp_string.end(), filter_exp);
    filter_exp[filter_exp_string.size()] = '\0';

    std::cout << "filter_exp" << filter_exp << std::endl;
    std::cout << strlen(filter_exp) << std::endl;

    msniffer = new sniffer(device, filter_exp);
    msniffer->start();
}

void MainWindow::on_pushButton_2_clicked()
{
    list<struct s_packet>::iterator packet_list_iterator;
    for (packet_list_iterator=msniffer->packet_list.begin();
         packet_list_iterator!=msniffer->packet_list.end();
         ++packet_list_iterator)
    {
        got_packet(reinterpret_cast<const u_char*>(packet_list_iterator->packet));
    }
    //std::string test = ui->lineEdit_src_ip->text().toStdString();
    //ui->label_2->setText((std::to_string(test.length())).c_str());
    //ui->label_2->setText(get_filter_exp());
}

/*
char* MainWindow::get_filter_exp()
{
    //char filter_and = " and ";
    //int length_and = strlen(filter_and);
    bool flag = false;
    std::string src_ip = ui->lineEdit_src_ip->text().toStdString();
    std::string src_port = ui->lineEdit_2_src_port->text().toStdString();
    std::string dst_ip = ui->lineEdit_4_dst_ip->text().toStdString();
    std::string dst_port = ui->lineEdit_3_dst_port->text().toStdString();
    std::string filter_and = " and ";
    std::string filter_exp = "";
    // src ip
    if (src_ip.length()) {
        flag = true;
        filter_exp += "src ";
        filter_exp += src_ip;
        filter_exp += " ";
    }
    // src port
    if (flag && src_port.length()) {
        filter_exp += filter_and;
        filter_exp += "src port ";
        filter_exp += src_port;
        filter_exp += " ";
    }
    else if (src_port.length()) {
        flag = true;
        filter_exp += "src port ";
        filter_exp += src_port;
        filter_exp += " ";
    }

    // dst ip
    if (flag && dst_ip.length()) {
        filter_exp += filter_and;
        filter_exp += "dst ";
        filter_exp += dst_ip;
        filter_exp += " ";
    }
    else if (dst_ip.length()) {
        flag = true;
        filter_exp += "dst ";
        filter_exp += dst_ip;
        filter_exp += " ";
    }

    if (flag && dst_port.length()) {
        filter_exp += filter_and;
        filter_exp += "dst port ";
        filter_exp += dst_port;
        filter_exp += " ";
    }
    else if (dst_port.length()) {
        flag = true;
        filter_exp += "dst port ";
        filter_exp += dst_port;
        filter_exp += " ";
    }


    ui->label_2->setText(std::to_string(filter_exp.size()).c_str());

    if (filter_exp.size()) {
        char *filter_exp_char = new char[filter_exp.size() + 1];
        std::copy(filter_exp.begin(), filter_exp.end(), filter_exp_char);
        ui->label_2->setText(filter_exp_char);
        return filter_exp_char;
    }
    else {
        char *filter_exp_char = "";
        ui->label_2->setText(filter_exp_char);
        return filter_exp_char;
    }
}
*/
