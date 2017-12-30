#-------------------------------------------------
#
# Project created by QtCreator 2017-12-17T16:13:58
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = 1
TEMPLATE = app

LIBS += -lpcap

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0


SOURCES += \
        main.cpp \
        mainwindow.cpp \
    sniffer.cpp \
    snifferthread.cpp \
    protocol.cpp \
    ip_defrag.cpp \
    save_dialog.cpp \
    save_packet_in_file.cpp \
    find_in_packets.cpp

HEADERS += \
        mainwindow.h \
    sniffer.h \
    snifferthread.h \
    protocol.h \
    ip_defrag.h \
    save_dialog.h

FORMS += \
        mainwindow.ui \
    save_dialog.ui
