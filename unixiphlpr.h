#ifndef UNIXIPHELPER_H
#define UNIXIPHELPER_H

#include "iphlpr.h"

#include <QHostAddress>
#include <QHostInfo>

struct TraceOptions
{
    QString destinationHostname;
    int destinationPort;
    int startTTL;
    int maxTTL;
    int timeoutPerHopMS;
    int totalTimeout;
    int numProbesPerHop;
};

class TraceWorker: public QObject
{
    Q_OBJECT

    TraceOptions mOptions;
    int mDNSLookupId = 0;
    int mRcvsock = -1;
    int mSndsock = -1;
    std::atomic_bool mShouldStop{false};
public:
    TraceWorker(const TraceOptions& options): QObject()
    , mOptions(options)
    {}

    virtual ~TraceWorker(){}
public slots:
    void process();
    void trace(const QHostInfo&);
    void stop();
signals:
    void ping(int distance, QString address, int rtt);
    void error();
};

class UnixIpHelper : public IpHelperObject
{
    Q_OBJECT
public:
    explicit UnixIpHelper(QObject *parent = nullptr);
    virtual ~UnixIpHelper() {}

public slots:
    virtual int asyncPing(const QString& strAddress, const QVariantMap& mapOptions = QVariantMap()) override;
    virtual int asyncTrace(const QString& strAddress, const QVariantMap& mapOptions = QVariantMap()) override;

    virtual int cancelAsync(bool bWait = true) override;

    virtual void ping(int distance, QString address, int rtt);

private slots:
    void trace();
    void handleError();
    void traceWorkerFinished();
private:
    QHostAddress m_destinationAddress;

    int m_ttl;					//REVIEW: max or total ttl for each hop????
    int m_nTotalTimeout = DEFAULT_TOTAL_TRACE_TIMEOUT;		//ticks internally
    int m_nTimeout = DEFAULT_ICMP_TIMEOUT;				//per-hop, passed to IcmpSendEcho2
    int m_nMaxHops = DEFAULT_ICMP_MAXHOPS;             //max that will be attempted
    int m_maxOutstanding = MAX_OUTSTANDING_PINGS;   //new: max concurrent pings
    int m_nQueuePerTTL = MAX_QUEUE_PER_TTL;     //new: how many to queue per hop
    int m_maxConsecutiveNullHops = MAX_CONSECUTIVE_NULL_HOPS; //new: stop tracing after null hop (-1 to keep going to max)
    int m_maxToRemoveAtEnd = MAX_NULL_HOPS_REMOVE_ATEND;
    int m_ipFlags;
    int m_origStartingTTL;      //record for computing hops
    bool m_bCanceled = false;
    bool m_bIsRunning = false;

    //running storage for the trace
    QVector<QVector<Ping> > m_hopList;
    QList<int> m_pingsPerHop;         //how many do we have out there for this TTL/hop
    TraceWorker* m_traceWorker;
    QThread* m_traceThread;
};

#endif // UNIXIPHELPER_H
