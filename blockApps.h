#ifndef BLOCKAPPS_H
#define BLOCKAPPS_H

#include "sharedRes.h"

class BlockApps {
    private:
        HANDLE blockApps;

    public:
        SharedList<const char *>dangerousApps;
        HANDLE start();
        void stop();
        HANDLE getHandleThread();    
};

DWORD WINAPI BlockAppsThread(LPVOID arg);



#endif