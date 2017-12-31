/********************************************************************************
** Form generated from reading UI file 'mainwindow.ui'
**
** Created by: Qt User Interface Compiler version 5.9.3
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MAINWINDOW_H
#define UI_MAINWINDOW_H

#include <QtCore/QVariant>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QButtonGroup>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QPlainTextEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QTableView>
#include <QtWidgets/QTreeView>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_MainWindow
{
public:
    QWidget *centralWidget;
    QPushButton *btn_find;
    QPushButton *btn_save;
    QPushButton *btn_dfg;
    QWidget *layoutWidget;
    QVBoxLayout *verticalLayout;
    QGridLayout *gridLayout;
    QLabel *device;
    QComboBox *comboBox;
    QPushButton *btn_run;
    QPushButton *btn_stop;
    QPushButton *btn_clear;
    QHBoxLayout *horizontalLayout_3;
    QLabel *label;
    QLineEdit *lineEdit;
    QTableView *packetTableView;
    QHBoxLayout *horizontalLayout;
    QTreeView *packetDetails;
    QPlainTextEdit *packetDataview;
    QPushButton *btn_rtn;
    QStatusBar *statusBar;

    void setupUi(QMainWindow *MainWindow)
    {
        if (MainWindow->objectName().isEmpty())
            MainWindow->setObjectName(QStringLiteral("MainWindow"));
        MainWindow->resize(802, 498);
        centralWidget = new QWidget(MainWindow);
        centralWidget->setObjectName(QStringLiteral("centralWidget"));
        btn_find = new QPushButton(centralWidget);
        btn_find->setObjectName(QStringLiteral("btn_find"));
        btn_find->setGeometry(QRect(700, 130, 81, 25));
        btn_save = new QPushButton(centralWidget);
        btn_save->setObjectName(QStringLiteral("btn_save"));
        btn_save->setGeometry(QRect(700, 190, 81, 25));
        btn_dfg = new QPushButton(centralWidget);
        btn_dfg->setObjectName(QStringLiteral("btn_dfg"));
        btn_dfg->setGeometry(QRect(700, 70, 80, 25));
        layoutWidget = new QWidget(centralWidget);
        layoutWidget->setObjectName(QStringLiteral("layoutWidget"));
        layoutWidget->setGeometry(QRect(24, 12, 661, 460));
        verticalLayout = new QVBoxLayout(layoutWidget);
        verticalLayout->setSpacing(6);
        verticalLayout->setContentsMargins(11, 11, 11, 11);
        verticalLayout->setObjectName(QStringLiteral("verticalLayout"));
        verticalLayout->setContentsMargins(0, 0, 0, 0);
        gridLayout = new QGridLayout();
        gridLayout->setSpacing(6);
        gridLayout->setObjectName(QStringLiteral("gridLayout"));
        device = new QLabel(layoutWidget);
        device->setObjectName(QStringLiteral("device"));

        gridLayout->addWidget(device, 0, 0, 1, 1);

        comboBox = new QComboBox(layoutWidget);
        comboBox->setObjectName(QStringLiteral("comboBox"));

        gridLayout->addWidget(comboBox, 0, 1, 1, 1);

        btn_run = new QPushButton(layoutWidget);
        btn_run->setObjectName(QStringLiteral("btn_run"));

        gridLayout->addWidget(btn_run, 0, 2, 1, 1);

        btn_stop = new QPushButton(layoutWidget);
        btn_stop->setObjectName(QStringLiteral("btn_stop"));

        gridLayout->addWidget(btn_stop, 0, 3, 1, 1);

        btn_clear = new QPushButton(layoutWidget);
        btn_clear->setObjectName(QStringLiteral("btn_clear"));

        gridLayout->addWidget(btn_clear, 0, 4, 1, 1);


        verticalLayout->addLayout(gridLayout);

        horizontalLayout_3 = new QHBoxLayout();
        horizontalLayout_3->setSpacing(6);
        horizontalLayout_3->setObjectName(QStringLiteral("horizontalLayout_3"));
        label = new QLabel(layoutWidget);
        label->setObjectName(QStringLiteral("label"));

        horizontalLayout_3->addWidget(label);

        lineEdit = new QLineEdit(layoutWidget);
        lineEdit->setObjectName(QStringLiteral("lineEdit"));

        horizontalLayout_3->addWidget(lineEdit);


        verticalLayout->addLayout(horizontalLayout_3);

        packetTableView = new QTableView(layoutWidget);
        packetTableView->setObjectName(QStringLiteral("packetTableView"));

        verticalLayout->addWidget(packetTableView);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setSpacing(6);
        horizontalLayout->setObjectName(QStringLiteral("horizontalLayout"));
        packetDetails = new QTreeView(layoutWidget);
        packetDetails->setObjectName(QStringLiteral("packetDetails"));

        horizontalLayout->addWidget(packetDetails);

        packetDataview = new QPlainTextEdit(layoutWidget);
        packetDataview->setObjectName(QStringLiteral("packetDataview"));

        horizontalLayout->addWidget(packetDataview);


        verticalLayout->addLayout(horizontalLayout);

        btn_rtn = new QPushButton(centralWidget);
        btn_rtn->setObjectName(QStringLiteral("btn_rtn"));
        btn_rtn->setGeometry(QRect(700, 240, 80, 25));
        MainWindow->setCentralWidget(centralWidget);
        statusBar = new QStatusBar(MainWindow);
        statusBar->setObjectName(QStringLiteral("statusBar"));
        MainWindow->setStatusBar(statusBar);

        retranslateUi(MainWindow);

        QMetaObject::connectSlotsByName(MainWindow);
    } // setupUi

    void retranslateUi(QMainWindow *MainWindow)
    {
        MainWindow->setWindowTitle(QApplication::translate("MainWindow", "MainWindow", Q_NULLPTR));
        btn_find->setText(QApplication::translate("MainWindow", "find", Q_NULLPTR));
        btn_save->setText(QApplication::translate("MainWindow", "save", Q_NULLPTR));
        btn_dfg->setText(QApplication::translate("MainWindow", "defrag", Q_NULLPTR));
        device->setText(QApplication::translate("MainWindow", "Choose device:", Q_NULLPTR));
        btn_run->setText(QApplication::translate("MainWindow", "run", Q_NULLPTR));
        btn_stop->setText(QApplication::translate("MainWindow", "stop", Q_NULLPTR));
        btn_clear->setText(QApplication::translate("MainWindow", "clear", Q_NULLPTR));
        label->setText(QApplication::translate("MainWindow", "filter expression", Q_NULLPTR));
        btn_rtn->setText(QApplication::translate("MainWindow", "return", Q_NULLPTR));
    } // retranslateUi

};

namespace Ui {
    class MainWindow: public Ui_MainWindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MAINWINDOW_H
