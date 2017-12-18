#-------------------------------------------------
#
# Project created by QtCreator 2017-11-23T15:56:55
#
#-------------------------------------------------

QT       += core gui
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = learn
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    listtreeview.cpp \
    getdevice.cpp \
    sniffer.cpp

HEADERS  += mainwindow.h \
    listtreeview.h \
    getdevice.h \
    sniffer.h

FORMS    += mainwindow.ui

LIBS += -L/usr/local/lib/ -lpcap

