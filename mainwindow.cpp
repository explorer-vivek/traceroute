#include "mainwindow.h"
#include "traceroute.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QTextEdit>
#include <QMessageBox>
#include <QPushButton>

#include "iphlpr.h"

class ContentView: public QWidget {
public:
    ContentView(QWidget* p): QWidget(p)
    {
        QHBoxLayout* hbl = new QHBoxLayout;
        QLabel* label = new QLabel("Hostname", this);

        QLineEdit* edit = new QLineEdit(this);
        edit->setPlaceholderText("www.google.com");

        QPushButton* cancel = new QPushButton("Cancel", this);

        hbl->addWidget(label);
        hbl->addWidget(edit);
        hbl->addWidget(cancel);

        QTextEdit* te = new QTextEdit(this);
        te->setReadOnly(true);

        QVBoxLayout* vbl = new QVBoxLayout;
        vbl->addLayout(hbl);
        vbl->addWidget(te);
        setLayout(vbl);

        auto helper = IpHelperObject::Create(this);

        connect(edit, &QLineEdit::returnPressed, [=](){
            QString hostname = edit->text();

            connect(helper, &IpHelperObject::pingResult, [=](const QVariantMap& map){
                int ttl = map["ttl"].toInt();
                QString address = map["address"].toString();
                int rtt = map["rtt"].toInt();
                QString log = QString("%1  %2     %3")
                                .arg(ttl, 2)
                                .arg(address)
                                .arg(!rtt ? "" : QString("%1 ms").arg(rtt));
                te->append(log);
            });

            connect(helper, &IpHelperObject::traceFinal, [=](){
//                QMessageBox msgBox;
//                msgBox.setText("failed");
//                msgBox.exec();

                edit->setEnabled(true);
                cancel->setDisabled(true);
                
                te->append("done");
                
                edit->setFocus();
            });

            edit->setDisabled(true);

            helper->asyncTrace(hostname);

            cancel->setDisabled(false);

            te->clear();
        });

        cancel->setDisabled(true);

        connect(cancel, &QPushButton::clicked, [=]() {
            helper->cancelAsync();
        });
    }
};

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setMinimumSize(QSize(600, 480));
    auto w = new ContentView(this);
    setCentralWidget(w);
}

MainWindow::~MainWindow()
{
}

