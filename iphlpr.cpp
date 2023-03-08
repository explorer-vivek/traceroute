#include "iphlpr.h"

IpHelperObject::IpHelperObject(QObject *parent)
    : QObject{parent}
{

}

int IpHelperObject::asyncPing(const QString& strAddress, const QVariantMap& mapOptions)
{
    return 0;
}

int IpHelperObject::asyncTrace(const QString& strAddress, const QVariantMap& mapOptions)
{
    return 0;
}

int IpHelperObject::cancelAsync(bool bWait)
{
    return 0;
}

bool IpHelperObject::isAsync()
{
    return false;
}

bool IpHelperObject::isCanceled() {
    return false;
}
bool IpHelperObject::isRunning() {
    return false;
}
