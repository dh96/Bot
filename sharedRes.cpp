#include "sharedRes.h"

void Slock::lock(){
    EnterCriticalSection(&critical_section);
}

void Slock::unlock() {
    LeaveCriticalSection(&critical_section);
}

Slock::Slock() {
    ret = InitializeCriticalSectionAndSpinCount(&critical_section, 0x80000400);
}

Slock::~Slock() {
    DeleteCriticalSection(&critical_section);
}

void SharedBool::operator=(const bool &rBoolArg) {
    sc.lock();
    rBool = rBoolArg;
    sc.unlock();
}


SharedBool &SharedBool::operator=(const SharedBool &sb) {
    sc = sb.sc;
    rBool = sb.rBool;
    return *this;
}

bool SharedBool::getValue() {
    //sc.lock();
    bool boolTmp = rBool;
    //sc.unlock();
    return boolTmp;
}