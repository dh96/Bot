#include "network.h"

Server::Server(std::string encryptionKeyArg){
    encryptionKey = encryptionKeyArg;
    port = "none";
    hThread = NULL;
    listenSocket = INVALID_SOCKET;
    sta.encryptionKey = encryptionKeyArg;
    sta.ListenSocket = INVALID_SOCKET;
}

Server &Server::operator=(const Server &server){
    encryptionKey = server.encryptionKey;
    port = server.port;
    hThread = server.hThread;
    listenSocket = server.listenSocket;

    sta.encryptionKey = server.sta.encryptionKey;
    sta.ListenSocket = server.sta.ListenSocket;
    return *this;
}

void Server::Start(std::string portArg, bool encrypted){
    DWORD dwThreadId;
    port = portArg;

    if(encrypted)
        sta.encryptionKey = encryptionKey;
    else
        sta.encryptionKey = "";

    SOCKET listenSocketTmp = INVALID_SOCKET;
    SharedList<HANDLE> *CLhandles = new SharedList<HANDLE>;
    sta.CLhandles = CLhandles;

     WSADATA wsaData;
     int iResult;

     struct addrinfo *result ,*rp;
     struct addrinfo hints;

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2,2),&wsaData);
    if(iResult != 0){
        //throw 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    // Resolve the server address and port
    iResult = getaddrinfo(NULL, portArg.c_str(), &hints, &result);
    if (iResult != 0) {
        WSACleanup();
        //throw 1;
    }

    // Setup TCP listing socket
    for (rp = result; rp != NULL; rp = rp->ai_next) {
               listenSocketTmp = socket(rp->ai_family, rp->ai_socktype,
                       rp->ai_protocol);
               if (listenSocketTmp == -1)
                   continue;

               if (bind(listenSocketTmp, rp->ai_addr,(int)rp->ai_addrlen) == 0)
                   break;                  /* Success */

               closesocket(listenSocketTmp);
           }
   

    freeaddrinfo(result);

    if (rp == NULL) {               /* No address succeeded */
        fprintf(stderr, "Could not bind\n");
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    iResult = listen(listenSocketTmp,SOMAXCONN); /* max num allowed */
    if(iResult == SOCKET_ERROR){
        closesocket(listenSocketTmp);
        WSACleanup();
        //throw 1;
    }

    listenSocket = listenSocketTmp;
    sta.ListenSocket = listenSocketTmp;
    sta.port = port;

    hThread = CreateThread(0,0,&ServerThread,(void*)&sta,0,&dwThreadId);

}   

void Server::Stop(){
    port = "";
    closesocket(listenSocket);
    WSACleanup();
    DWORD dwExit;
    GetExitCodeThread(hThread,&dwExit);
    TerminateThread(hThread,dwExit);
    CloseHandle(hThread);
}

HANDLE Server::gethThread() {
    return hThread;
}

std::string Server::getPort() {
    return port;
}

DWORD WINAPI ServerThread(void *arg){
    std::string encryptionKey = (*((ServerThreadArgs *)arg)).encryptionKey;
    SOCKET ListenSocket = (*((ServerThreadArgs *)arg)).ListenSocket;
    std::string port = (*((ServerThreadArgs *)arg)).port;
    SharedList<HANDLE > *CLhandles = (*((ServerThreadArgs *)arg)).CLhandles;
    
    SOCKET ClientSocket = INVALID_SOCKET;
    while(true){
        //Accept a client socket
        printf("listen for connections on port %s ...\n", port); //debug
        ClientSocket = accept(ListenSocket,NULL,NULL);
        if(ClientSocket == INVALID_SOCKET){
            closesocket(ClientSocket);
            WSACleanup();
            return 1;
        } else {
            ClientSocketThreadArgs csa;
            csa.ClientSocket = ClientSocket;
            csa.encryptionKey = encryptionKey;
            csa.CLhandles = CLhandles;
            CLhandles->add(CreateThread(0,0,&ClientSocketThread,(void*)&csa,0,NULL));
        }
    }

    return 0;
}

DWORD WINAPI ClientSocketThread(void *arg){
    std::string encryptionKey = (*((ClientSocketThreadArgs *)arg)).encryptionKey; 
    SOCKET ClientSocket = (*((ClientSocketThreadArgs *)arg)).ClientSocket;
    SharedList<HANDLE>*CLhandles = (*((ClientSocketThreadArgs *)arg)).CLhandles;
    
    //Crypto crypto(encryptionkey);
    const int bufferlength = 512;
    int iResult;

    std::string command;
    std::string response;
    int iSendResult;
    char recvbuf[bufferlength];
    std::size_t posSubStr;

    //Receive until the peer shuts down the connection
    /*if (encryptionKey.compare("") != 0) {
        send(ClientSocket, "\nEncrypted Connection Established\n", 34, 0);
    } else {
        send(ClientSocket, "\nConnection Established\n", 24, 0);
    }*/

    iSendResult = send(ClientSocket, "\nConnection Established\n", 24, 0);
    if(iSendResult == -1){
        printf("Sending failed: %d\n",errno);
        closesocket(ClientSocket);
        CLhandles->remove(GetCurrentThread());
        std::terminate();

    }


    do {
        memset(&recvbuf,0,sizeof(recvbuf));
        iResult = recv(ClientSocket, recvbuf,bufferlength,0);

        if (iResult == -1){
            printf("Receiving failed: %d\n",errno);
            closesocket(ClientSocket);
            CLhandles->remove(GetCurrentThread());
            std::terminate();
        }

        command.append(recvbuf);

        //string decryption
        /*if (encryptionKey.compare("") != 0) {
            command.erase(command.find("\r\n"), command.length());
            command = crypto.Decrypt(command);
            command.append("\r\n");
        */
       
        posSubStr = command.find("\n");

        if (posSubStr != std::string::npos) {
            //erase escape characters
            command.erase(posSubStr);
            
            //debug, muss noch entfernt werden
            printf("before cmdDispatcher: %s\n",command);
            response = CommandDispatcher(command);
            printf("after cmdDispatcher: %s\n",command);


            // string encryption
            /*if (encryptionKey.compare("") != 0) {
                std::string encResponse = (crypto.Encrypt(response) + "\n");
                iSendResult = send(ClientSocket, encResponse.c_str(), encResponse.length(), 0);
            } else {
                iSendResult = send(ClientSocket, response.c_str(), response.length(), 0);
            }*/

            iSendResult = send(ClientSocket, response.c_str(), response.length(), 0);

            if (iSendResult == SOCKET_ERROR) {
                closesocket(ClientSocket);
                CLhandles->remove(GetCurrentThread());
                std::terminate();
            }
        }
        command.clear();

    } while (iResult > 0 && response.compare("***quit***") != 0);

    iSendResult = send(ClientSocket, "\nConnection Stopped\n", 20, 0);

    if (iSendResult == SOCKET_ERROR) {
         closesocket(ClientSocket);
         CLhandles->remove(GetCurrentThread());
         std::terminate();
        }
    
    //shutdown the connection
    iResult = shutdown(ClientSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        closesocket(ClientSocket);
        CLhandles->remove(GetCurrentThread());
        std::terminate();
    }
    return 0;
}


Device::Device(std::string nameArg, std::string serverPortArg) {
    name = nameArg;
    serverPort = serverPortArg;
}

Device &Device::operator=(const Device &device) {
    name = device.name;
    serverPort = device.serverPort;
    return *this;
}

std::string Device::getName() {
    return name;
}

std::string Device::getServerPort() {
    return serverPort;
}

void Device::setName(std::string nameArg) {
    name = nameArg;
}

void Device::setServerPort(std::string serverPortArg) {
    serverPort = serverPortArg;
}

Network &Network::operator=(const Network &network) {
    encryptionKey = network.encryptionKey;
    defaultEncryptionKey = network.defaultEncryptionKey;
    serverAddress = network.serverAddress;
    port = network.port;
    associatedUser = network.associatedUser;
    server = network.server;
    return *this;
}

Network::Network(const std::string& encryptionKeyArg) {
    encryptionKey = encryptionKeyArg;
    server = Server(encryptionKeyArg);
}

Network::Network(const std::string &serverAddressArg, const std::string &portArg,
                 const std::string &associatedUserArg,
                 const std::string &encryptionKeyArg) {
    serverAddress = serverAddressArg;
    port = portArg;
    associatedUser = associatedUserArg;
    encryptionKey = encryptionKeyArg;
    //defaultEncryptionKey = "";
    server = Server(encryptionKeyArg);
}

Network::Network(const std::string &serverAddressArg, const std::string &portArg,
                 const std::string &associatedUserArg,
                 const std::string &encryptionKeyArg, const std::string &defaultEncryptionKeyArg) {
    serverAddress = serverAddressArg;
    port = portArg;
    associatedUser = associatedUserArg;
    encryptionKey = encryptionKeyArg;
    defaultEncryptionKey = defaultEncryptionKeyArg;
    server = Server(encryptionKeyArg);
}

std::string Network::RawRequest(const std::string &serverAddress, const std::string &port, const std::string &request){
    WSADATA wsaData;
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct addrinfo *result = NULL, *ptr =NULL, hints;
    const char *sendbuf = request.c_str();
    const int bufferlength = 512;
    char recvbuf[bufferlength];
    int iResult;
    std::string response;

    printf("RawRequest: %s port: %s",serverAddress.c_str(),port.c_str());

    //Init Winsock
    iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0){
        return "Error: WSAStartup";
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    iResult = getaddrinfo(serverAddress.c_str(),port.c_str(),&hints,&result);
    if(iResult != 0){
        WSACleanup();
        return "Error: getaddrinfo";
    }

     // Attempt to connect to an address until one succeeds
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {

        // Create a SOCKET for connecting to server
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
                               ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) {
            WSACleanup();
            return "Error: socket";
        }

        // Connect to server.
        iResult = connect(ConnectSocket, ptr->ai_addr, (int) ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(result);
    freeaddrinfo(ptr);

    if (ConnectSocket == INVALID_SOCKET) {
        WSACleanup();
        return "Error: connect";
    }

    // Receive until the peer closes the connection
    do {
        iResult = recv(ConnectSocket, recvbuf, bufferlength, 0);
        if (iResult > 0) {
            // answer
            response.append(recvbuf);
        } else if (iResult == 0) {
            // connection closed
        } else {
            // error
        }

    } while (iResult > 0);


     // shutdown the connection since no more data will be sent
    iResult = shutdown(ConnectSocket, SD_SEND);

    if (iResult == SOCKET_ERROR) {
        closesocket(ConnectSocket);
        WSACleanup();
        return "Error: shutdown";
    }

    // cleanup
    closesocket(ConnectSocket);
    WSACleanup();

    return response;

}

