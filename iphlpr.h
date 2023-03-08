#ifndef IPHELPEROBJECT_H
#define IPHELPEROBJECT_H

#include <QObject>
#include <QVariantMap>
#include <QHostAddress>

#include <sys/socket.h>

const int DEFAULT_ICMP_TIMEOUT			= 4000;
const int DEFAULT_TCPIP_TIMEOUT			= 10000; // 10 seconds
const int DEFAULT_ICMP_COUNT			= 5;
const int DEFAULT_ICMP_SIZE				= 48;
const int DEFAULT_ICMP_MAXHOPS			= 30;           //lowering and matching tracert (for now)
const int DEFAULT_TOTAL_TRACE_TIMEOUT	= 120 * 1000;  ///120 seconds since we are going to ping a few more times
const int DEFAULT_TCP_COUNT				= 3;
const int DEFAULT_TTL					= 64;
const int MAX_TTL						= 64;
const int MAX_PACKET_SIZE				= 1400; //could even be 1500? MTU but that's typicall lower. We'll put it at 1400
const int MAX_OUTSTANDING_PINGS         = 10;   //defaulting to 2 per hop and 10 oustanding means we will not abort at 1st couple hops (like verizon wants to do)
const int MAX_QUEUE_PER_TTL             = 2;
const int ALLOCATE_ECHO_REPLIES         = 4; //incase its a broadcast address which it shouldn't be

//now that we might be sending more packets concurrently, we want to do some randomization
// and throttling a little bit
const int PACKET_INTERVAL               = 250; //ms spacing between send batches
const int MIN_PACKET_INTERVAL           = 20;
const int PACKET_SEND_BATCHES           = 1; //batches of packets to send at once. we were sending more but default to 1
const int MAX_CONSECUTIVE_NULL_HOPS     = 5; //
const int MAX_NULL_HOPS_REMOVE_ATEND    = 5; //increased this to 5 recently

// win specific: to be moved to win32hlpr.h
//const int DEFAULT_IP_FLAGS              = IP_FLAG_DF;
//const bool DEFAULT_USE_APC              = false;

//special new optional flags for the trace
#define TRACE_FLAGS_DONTPINGDEST				0x00000001			//don't ping the dest if last hop trace fails
#define TRACE_FLAGS_DONTTCPDEST					0x00000002			//don't try and TCPIP connect to last hop if trace fails
#define TRACE_FLAGS_WAITFORLOOKUP               0x00000004          //wait for lookups to finish before emitting final trace

#define TRACE_FLAGS_DONTSKIPFIRSTHOP			0x00000010			//don't skip first hop (self)
#define TRACE_FLAGS_DONTEATHOPSATEND			0x00000020			//don't eat bad hops at the end
#define TRACE_FLAGS_DONTAPPENDPSUEDO_HOP		0x00000040			//don't append psuedo hop if everything fails
#define TRACE_FLAGS_DONTEATDUPEHOPSATEND        0x00000080          //don't eat duplicate detected hops at the end

//responding address treatment
#define TRACE_FLAGS_INCLUDE_ALL_ADDRS   		0x00000080			//include all responding addresses for a hop
#define TRACE_FLAGS_INCLUDE_NONUNIQUE_ADDRS     0x00000100
#define TRACE_FLAGS_DONTEXTRAHOP                0x00000200          //by default,we go past the successful ping by 1 and then eat it up if its the same (verizon spoof handling)
#define TRACE_FLAGS_DONT_REMOVE_SPOOFED         0x00000400          //by default,we remove spoofed hops

#define TCP_TABLE_FLAGS_INCLUDE_ALL             0x00000001          //only include open
#define TCP_TABLE_FLAGS_INCLUDE_OPEN            0x00000002          //by default we only include established
#define TCP_TABLE_FLAGS_SKIP_LOCALHOST          0x00000004          //don't include localhost

#define TCP_TABLE_FLAGS_DEFAULT                 TCP_TABLE_FLAGS_INCLUDE_OPEN | TCP_TABLE_FLAGS_SKIP_LOCALHOST
#define TRACE_FLAGS_DEFAULT                     TRACE_FLAGS_WAITFORLOOKUP | TRACE_FLAGS_INCLUDE_ALL_ADDRS

//rename this, it represents a single probe of an address or hop
class Ping
{
public:
    Ping() :
        rtt(0)
      , status()
      , ttl(0)
      , recvTTL(0)
      , dwError(0)
      , address()
      , icmpStatus(0)
    {
    }


#ifdef Q_OS_WIN
    void setReply(PICMP_ECHO_REPLY pReply)
    {
        address.sin.sin_addr.s_addr = pReply->Address;
        //really don't know what the hell this TTL is, should stop looking at it, really
        ttl = pReply->Options.Ttl;
        //qDebug("%s: reply ttl: %d", __FUNCTION__, ttl);
        rtt = pReply->RoundTripTime;
        status = pReply->Status;
    }

    void setReply(PICMPV6_ECHO_REPLY pReply, int optionsTTL = 0)
    {
        memcpy(&address.sin6.sin6_addr, pReply->Address.sin6_addr, sizeof(pReply->Address.sin6_addr));
        ttl = optionsTTL;// pReply->Options.Ttl;
        rtt = pReply->RoundTripTime;
        status = pReply->Status;
    }
#else
    void setReply(quint32 inaddr, qint64 rtt, long status,int ttl)
    {
//        this->address.sin.sin_addr.s_addr = (unsigned int)inaddr;
        this->ttl = (quint32)ttl;
        this->status = status;
        this->rtt = rtt;
    }
#endif

    //will this work?
    bool sameAddress(const Ping& ping) {
        return address == ping.address;
    }

    bool isIPV4(quint32 ipv4) {
        return address.protocol() == QAbstractSocket::IPv4Protocol;
    }

    QString ipString() {
        return address.toString();
    }

    QHostAddress address;
    quint32	rtt;
    quint32	status;
    quint32	ttl;
    quint32 recvTTL;
    quint32	dwError;
    quint32 icmpStatus;
    bool isNullAddress() { return address.isNull(); }
    bool isValidAndNotNull() { return isValid() && !isNullAddress(); }
    bool isValid() { return status == 0;  }
    void toMap(QVariantMap& map);
    void toHop(int hop, QVariantMap& map, int startTTL);
};


class IpHelperObject : public QObject
{
    Q_OBJECT
public:
    explicit IpHelperObject(QObject *parent = nullptr);
    virtual ~IpHelperObject() = default;

    static IpHelperObject* Create(QObject* parent);
public:
    bool isTraceable(const QHostAddress& addr)
    {
    #if QT_VERSION <= QT_VERSION_CHECK(5, 10, 1)
        if (addr.isLoopback())
            return false;
        return true; // addr.isGlobal();
    #else
        if (addr.isBroadcast() ||
            addr.isLoopback() ||
            addr.isLinkLocal())
            return false;
        return addr.isGlobal();
    #endif
    }
public slots:
    virtual int asyncPing(const QString& strAddress, const QVariantMap& mapOptions = QVariantMap());
    virtual int asyncTrace(const QString& strAddress, const QVariantMap& mapOptions = QVariantMap());

    virtual int cancelAsync(bool bWait = true);
    virtual bool isAsync();
    virtual bool isCanceled();
    virtual bool isRunning();
signals:
    //you can connect up to intermediate signals of
    // the pings of a trace and the hops
    void pingResult(const QVariantMap& map); //indivdual ping
    void pingFinal(const QVariantMap& map);	//ping final

    //for trace you get a pingResult, then traceHop, then traceFinal
    void traceHop(const QVariantMap& map);
    void traceHost(const QVariantMap& map);		//trace host lookup
    void traceFinished(const QVariantMap& map); //trace part is done but we may still ping or connect
    void traceFinal(const QVariantMap& map);	//trace final after everything

    void hostLookup(const QVariantMap& map);
};

#endif // IPHELPEROBJECT_H
