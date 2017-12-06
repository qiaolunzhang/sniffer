#ifndef LISTTREEVIEW_H
#define LISTTREEVIEW_H

#include <QTreeView>

class QStandardItemModel;
class QModelIndex;
class QString;

class ListTreeView : public QTreeView
{
    Q_OBJECT

public:
    ListTreeView();
    ~ListTreeView();

    void rebuildInfo();
    void addOneCaptureItem(QString strNum, QString strTime, QString strSIP,QString strDIP, QString strProto, QString strLength);

    QStandardItemModel *mainModel;

private:
    int iPosition;
};
#endif // LISTTREEVIEW_H

