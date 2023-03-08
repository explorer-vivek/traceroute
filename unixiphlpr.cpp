#include "unixiphlpr.h"

#include <QHostInfo>
#include <QDebug>
#include <QThread>

#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <poll.h>
#include <arpa/inet.h>

const char *
icmp_type(u_char t)
{
    static const char *ttab[] = {
        "Echo Reply",	"ICMP 1",	"ICMP 2",	"Dest Unreachable",
        "Source Quench", "Redirect",	"ICMP 6",	"ICMP 7",
        "Echo",		"ICMP 9",	"ICMP 10",	"Time Exceeded",
        "Param Problem", "Timestamp",	"Timestamp Reply", "Info Request",
        "Info Reply"
    };
    
    if (t > 16)
        return("OUT-OF-RANGE");
    
    return(ttab[t]);
}

/*
 * Checksum routine for Internet Protocol family headers (C Version)
 */
static u_short
in_cksum(u_short *addr, int len)
{
    int nleft = len;
    u_short *w = addr;
    u_short answer;
    int sum = 0;
    
    /*
     *  Our algorithm is simple, using a 32 bit accumulator (sum),
     *  we add sequential 16 bit words to it, and at the end, fold
     *  back all the carry bits from the top 16 bits into the lower
     *  16 bits.
     */
    while (nleft > 1)  {
        sum += *w++;
        nleft -= 2;
    }
    
    /* mop up an odd byte, if necessary */
    if (nleft == 1)
        sum += *(u_char *)w;
    
    /*
     * add back carry outs from top 16 bits to low 16 bits
     */
    sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
    sum += (sum >> 16);			/* add carry */
    answer = ~sum;				/* truncate to 16 bits */
    return (answer);
}

IpHelperObject* IpHelperObject::Create(QObject* parent) {
    return new UnixIpHelper(parent);
}

UnixIpHelper::UnixIpHelper(QObject *parent)
: IpHelperObject{parent}
, m_traceWorker{nullptr}
, m_traceThread{nullptr}
{
    m_hopList.reserve(m_nMaxHops);
}

int UnixIpHelper::cancelAsync(bool bWait)
{
    if (m_traceWorker) {
        m_traceWorker->stop();
    }
    
    if (m_traceThread) {
        m_traceThread->quit();
        m_traceThread->wait();
    }
}

void TraceWorker::process()
{
    mDNSLookupId = QHostInfo::lookupHost(mOptions.destinationHostname, this, &TraceWorker::trace);
}

void TraceWorker::stop()
{
    qDebug() << "begin stop";
    mShouldStop = true;
    
    if (mDNSLookupId) {
        QHostInfo::abortHostLookup(mDNSLookupId);
        mDNSLookupId = 0;
    }
    
    if (mRcvsock != -1)
        close(mRcvsock);
    if (mSndsock != -1)
        close(mSndsock);
    qDebug() << "endstop";
}

void TraceWorker::trace(const QHostInfo& hostInfo)
{
    
    if (hostInfo.error() != QHostInfo::NoError) {
        emit error();
        return;
    }
    
    // TODO: what if the ip is v6?
    auto destinationAddress = hostInfo.addresses().first();
    
    qDebug() << "Begin trace for " << destinationAddress.toString();
    
    // create a raw icmp socket
    mRcvsock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (mRcvsock < 0) {
        emit error();
        return;
    }
    
    mSndsock = socket(AF_INET, SOCK_DGRAM, 0);
    if (mSndsock < 0) {
        emit error();
        return;
    }
    
    sockaddr_in destsa;
    memset(&destsa, 0, sizeof (destsa));
    destsa.sin_family = AF_INET;
    destsa.sin_addr.s_addr = htonl(destinationAddress.toIPv4Address());
    int identity = getpid() & 0xffff;
    int sport = identity | 0x8000;
    
    sockaddr_in bindsa;
    memset(&bindsa, 0, sizeof (bindsa));
    bindsa.sin_family = AF_INET;
    bindsa.sin_port = htons(sport);
    if (bind(mSndsock, (sockaddr*) &bindsa, sizeof (bindsa)) < 0) {
        emit error();
        return;
    }
    
    short seq = 0;
    
    for (int ttl = mOptions.startTTL; ttl <= mOptions.maxTTL && !mShouldStop; ++ttl) {
        if (setsockopt(mSndsock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
            emit error();
            return;
        }
        
        for (int i = 0; i < mOptions.numProbesPerHop; ++i) {
            // prepare probe
            char probe[64] = {0};
            destsa.sin_port = htons(mOptions.destinationPort + ++seq);
            qDebug() << "send probe ttl:"  << ttl << "sport:" << sport << "dport:" << ntohs(destsa.sin_port);
            auto bytesWritten = sendto(mSndsock, probe, sizeof (probe), 0, (sockaddr*) &destsa, sizeof(destsa));
            if (bytesWritten < 0 || bytesWritten != sizeof (probe)) {
                emit error();
                return;
            }
            
            QElapsedTimer timer;
            timer.start();
            
            while(true) {
                if (timer.elapsed() >= mOptions.timeoutPerHopMS) {
                    qDebug() << "timer expired for ttl:" << ttl;
                    emit ping(ttl, "*", 0);
                    break;
                }
                
                
                fd_set fdset;
                FD_ZERO(&fdset);
                FD_SET(mRcvsock, &fdset);
                
                timeval timeout;
                int remainingTimeout = mOptions.timeoutPerHopMS - timer.elapsed();
                timeout.tv_sec = remainingTimeout/1000;
                timeout.tv_usec = (remainingTimeout - timeout.tv_sec * 1000) * 1000;
                int nready = select(mRcvsock + 1, &fdset, NULL, NULL, &timeout);
                
                if (nready == -1 && nready == EINVAL) {
                    emit error();
                    return;
                }
                
                if (nready == 0) {
                    qDebug() << "select timeout ";
                    continue;
                }
                
                if (FD_ISSET(mRcvsock, &fdset)) {
                    char ippacket[IP_MAXPACKET] = {0};
                    sockaddr_in fromsa;
                    memset(&fromsa, 0, sizeof(fromsa));
                    socklen_t fromlen = sizeof(fromsa);
                    int bytesRead = recvfrom(mRcvsock, ippacket, sizeof (ippacket), 0, (sockaddr*) &fromsa, &fromlen);
                    if (bytesRead < 0) {
                        if (errno == EBADF
                            && mShouldStop) {
                            break;
                        }
                        if (errno == EINTR) {
                            qDebug() << "EINTR";
                            continue;
                        }
                        else {
                            emit error();
                            break;
                        }
                    }
                    
                    ip* iphdr = (ip *) ippacket;
                    int iphdrlen = iphdr->ip_hl << 2;
                    
                    icmp* icmphdr = (icmp*) ((char*)&ippacket[0] + iphdrlen);
                    
                    if (bytesRead - iphdrlen < ICMP_MINLEN)
                        continue;
                    
                    if ((icmphdr->icmp_type == ICMP_TIMXCEED &&
                         icmphdr->icmp_code == ICMP_TIMXCEED_INTRANS)
                        || icmphdr->icmp_type == ICMP_UNREACH) {
                        ip* innerIpHdr = (ip*) &icmphdr->icmp_ip;
                        int innerIpHdrLen = innerIpHdr->ip_hl << 2;
                        
                        if (bytesRead - (innerIpHdr - iphdr) - innerIpHdrLen < 4)
                            continue;
                        
                        udphdr* udp = (udphdr*) (((char*)innerIpHdr) + innerIpHdrLen);
                        
                        if (innerIpHdr->ip_p == IPPROTO_UDP
                            && udp->uh_sport == htons(sport)
                            && udp->uh_dport == destsa.sin_port) {
                            qDebug() << ttl << "response from " << QHostAddress(ntohl(fromsa.sin_addr.s_addr)).toString();
                            emit ping(ttl, inet_ntoa(fromsa.sin_addr), timer.elapsed());
                            
                            if (icmphdr->icmp_code == ICMP_UNREACH_PORT) {
                                mShouldStop = true;
                            }
                            break;
                        }
                        
                        continue;
                        
                    } else {
                        qDebug() << "unrecognized icmp type" << icmp_type((uchar)icmphdr->icmp_type);
                        continue;
                    }
                }
            }
        }
    }
    
    
    
    close(mRcvsock);
    close(mSndsock);
    mRcvsock = mSndsock = -1;
    
    thread()->quit();
}

int UnixIpHelper::asyncTrace(const QString& strAddress, const QVariantMap& mapOptions)
{
    if (strAddress.isEmpty() || isRunning()) {
        return -1;
    }
    
    m_traceThread = new QThread();
    m_traceThread->setObjectName("Trace thread");
    
    TraceOptions options;
    options.destinationHostname = strAddress;
    options.startTTL = 1;
    options.maxTTL = 64;
    options.numProbesPerHop = 1;
    options.destinationPort = 33434;
    options.timeoutPerHopMS = 3000;
    m_traceWorker = new TraceWorker(options);
    m_traceWorker->moveToThread(m_traceThread);
    
    connect(m_traceThread, &QThread::started, m_traceWorker, &TraceWorker::process);
    connect(m_traceWorker, &TraceWorker::error, m_traceThread, &QThread::quit);
    connect(m_traceWorker, &TraceWorker::error, this, &UnixIpHelper::handleError);
    connect(m_traceThread, &QThread::finished, this, &UnixIpHelper::traceWorkerFinished);
    connect(m_traceWorker, &TraceWorker::ping, this, &UnixIpHelper::ping);
    m_traceThread->start();
    
    m_bIsRunning = true;
    
    return 0;
}

void UnixIpHelper::ping(int distance, QString address, int rtt)
{
    QVariantMap map;
    map["ttl"] = distance;
    map["rtt"] = rtt;
    map["address"] = address;
    emit pingResult(map);
}

void UnixIpHelper::handleError()
{

}

void UnixIpHelper::traceWorkerFinished()
{
    emit traceFinal(QVariantMap{{}});
    
    disconnect();
    
    delete m_traceThread;
    m_traceThread = nullptr;
    
    delete m_traceWorker;
    m_traceWorker = nullptr;
    
    m_bIsRunning = false;
    qDebug() << "trace worker finished";
}

int UnixIpHelper::asyncPing(const QString& strAddress, const QVariantMap& mapOptions)
{
    
}

void UnixIpHelper::trace()
{
    
}
