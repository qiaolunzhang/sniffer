#include "save_dialog.h"
#include "ui_save_dialog.h"

Save_Dialog::Save_Dialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Save_Dialog)
{
    ui->setupUi(this);

    // create and populate our model
    model = new QDirModel(this);

    // enable modifying file system
    model->setReadOnly(false);

    // tie treeview with qdirmodel
    // QtreeView::setModel(QAbstractItemMOdel *model)
    // Reimplemented from QAbstractItemView::setModel()
    ui->treeView->setModel(model);

    // set initial selection
    QModelIndex index = model->index("../");

    // set initial view of directory
    // for the selected drive as expanded
    ui->treeView->expand(index);

    // make it scroll to the selected
    ui->treeView->scrollTo(index);

    // Highlight the selected
    ui->treeView->setCurrentIndex(index);

    // Resizing the column - first column
    ui->treeView->resizeColumnToContents(0);
}

Save_Dialog::~Save_Dialog()
{
    delete ui;
}

void Save_Dialog::on_pushButton_clicked()
{
    QModelIndex index = ui->treeView->currentIndex();
    if(!index.isValid()) return;

    QString name = QInputDialog::getText(this, "Name", "Enter a name");

    if(name.isEmpty()) return;


    QModelIndex current_directory =  ui->treeView->currentIndex();
    QFileInfo fileInfo = model->fileInfo(current_directory);

    QString dir_name = fileInfo.absoluteFilePath();
    name = dir_name + '/' + name;
    //std::cout << name.toStdString() << std::endl;

    QFile file(name);
    if (file.open(QIODevice::ReadWrite)) {
        QTextStream stream(&file);
        stream << "something" << endl;
    }
}


