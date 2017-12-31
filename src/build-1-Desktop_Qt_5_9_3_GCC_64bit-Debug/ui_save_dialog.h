/********************************************************************************
** Form generated from reading UI file 'save_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.9.3
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_SAVE_DIALOG_H
#define UI_SAVE_DIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QButtonGroup>
#include <QtWidgets/QDialog>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTreeView>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_Save_Dialog
{
public:
    QWidget *widget;
    QVBoxLayout *verticalLayout;
    QTreeView *treeView;
    QPushButton *pushButton;

    void setupUi(QDialog *Save_Dialog)
    {
        if (Save_Dialog->objectName().isEmpty())
            Save_Dialog->setObjectName(QStringLiteral("Save_Dialog"));
        Save_Dialog->resize(400, 300);
        widget = new QWidget(Save_Dialog);
        widget->setObjectName(QStringLiteral("widget"));
        widget->setGeometry(QRect(10, 10, 381, 281));
        verticalLayout = new QVBoxLayout(widget);
        verticalLayout->setObjectName(QStringLiteral("verticalLayout"));
        verticalLayout->setContentsMargins(0, 0, 0, 0);
        treeView = new QTreeView(widget);
        treeView->setObjectName(QStringLiteral("treeView"));

        verticalLayout->addWidget(treeView);

        pushButton = new QPushButton(widget);
        pushButton->setObjectName(QStringLiteral("pushButton"));

        verticalLayout->addWidget(pushButton);


        retranslateUi(Save_Dialog);

        QMetaObject::connectSlotsByName(Save_Dialog);
    } // setupUi

    void retranslateUi(QDialog *Save_Dialog)
    {
        Save_Dialog->setWindowTitle(QApplication::translate("Save_Dialog", "Dialog", Q_NULLPTR));
        pushButton->setText(QApplication::translate("Save_Dialog", "save", Q_NULLPTR));
    } // retranslateUi

};

namespace Ui {
    class Save_Dialog: public Ui_Save_Dialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_SAVE_DIALOG_H
