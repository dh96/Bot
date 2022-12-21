#include "blockApps.h"

HANDLE BlockApps::start(){
    blockApps = CreateThread(0,0,&BlockAppsThread,&dangerousApps,0,0);

    WaitForSingleObject(blockApps,INFINITE); 
    CloseHandle(blockApps);
    return blockApps;

}

void BlockApps::stop() {
    SuspendThread(blockApps);
}

HANDLE BlockApps::getHandleThread() {
    return blockApps;
}

DWORD WINAPI BlockAppsThread(LPVOID arg){
    SharedList<const char *> Sl = *((SharedList<const char *> *) arg);
    std::list<const char *> dangerApps = Sl.getCopy();
    HWND app_handler;

    while(1){
        for (std::list<const char*>::iterator it = dangerApps.begin();
            it != dangerApps.end();++it){
                app_handler = FindWindowA (*it,NULL); 
                if(app_handler != NULL)
                    PostMessageA(app_handler,WM_CLOSE,(LPARAM)0,(WPARAM)0);       
            }
            Sleep(5000);
            dangerApps = Sl.getCopy();
    }

    
}

