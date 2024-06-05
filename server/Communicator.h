#pragma once
#include <iostream>
#include <map>
#include <stdexcept>
#include <thread>
#include <exception>
#include <unordered_map>
#include <sys/stat.h>
#include <filesystem>
#include <mutex>
#include <chrono>
#include <cstdlib> // For system function
#include <cstdio> // For popen and pclose
#include <string>
#include "Client.h"
#include "helper.h"
#include "Operations.h"
#include "FileOperation.h"
#include "IDatabase.h"

#pragma comment(lib, "ws2_32.lib")  // Add this lin

#define PORT 12345
#define CLOUD_PORT 5555
#define BUFFER_SIZE 4096

struct Action
{
    int code;
    std::string dataLength;
    std::string data;
    std::string index;
    std::string newLineCount;
    std::string selectionLength;

    long long timestamp; // Timestamp indicating when the action was created

    std::string fileName;
    std::string fileNameLength;
    int fileId;

    std::string msg;

    int userNameLength; // login/ signup
    std::string userName;

    std::string pass;
    int passLength;

    std::string oldPass; // forgot password
    int oldPassLength;

    std::string email;
    int emailLength;

    int size;
    int userId;
};

class Communicator {
private:
    SOCKET m_serverSocket;
    std::map<SOCKET, ClientHandler*> m_clients;
    std::map<std::string, std::vector<Action>> m_lastActionMap; // fileName : <lastAction, index>
    std::map<std::string, std::vector<ClientHandler>> m_usersOnFile; // fileName : users

    std::map<std::string, int> m_fileNames; // name, id
    std::map<std::string, std::string> m_filesData; // name, data
    std::map<std::string, bool> m_FileUpdate; // name, there was a change since last update

    std::unordered_map<std::string, std::mutex> m_fileMutexes;

    Operations operationHandler;
    FileOperation fileOperationHandler;
    IDatabase* m_database;

    std::string executeCommand(const std::string& command);
public:
    // Constructor
    Communicator();

    // Destructor
    ~Communicator();

    void setDB(IDatabase* db);
    void startHandleRequests();
    void bindAndListen();
    void handleNewClient(SOCKET client_sock);

    void updateFileOnServer(const std::string& filePath, const Action& reqDetail);

    void handleClientDisconnect(SOCKET client_sock);
    void handleError(SOCKET client_sock, std::exception a);
    long long getCurrentTimestamp();

    void notifyAllClients(const std::string& updatedContent, SOCKET client_sock, const bool isOnFile);

    Action deconstructReq(const std::string& req);
    Action adjustIndexForSync(const std::string& fileName, Action reqDetail);

    void login(SOCKET client_sock, std::string username, std::string pass, std::string mail);
    void logout(SOCKET client_sock);
    void signUp(SOCKET client_sock, std::string username, std::string pass, std::string mail);
    void forgotPassword(SOCKET client_sock, std::string username, std::string pass, std::string oldPass, std::string mail);
    void createFile(SOCKET client_sock, std::string fileName);
    void deleteFile(SOCKET client_sock, std::string fileName);
    void getFiles(SOCKET client_sock);
    void getInitialContent(SOCKET client_sock, std::string fileName);
    void joinFile(SOCKET client_sock, std::string fileName, std::string fileNameLen);
    void leaveFile(SOCKET client_sock);
    void getMesegges(SOCKET client_sock, std::string fileName);
    void getUsersOnFile(SOCKET client_sock, std::string fileName);
    void getUsers(SOCKET client_sock);
    void getUserPermissionReq(SOCKET client_sock);
    void postMsg( SOCKET client_sock, std::string fileName, std::string data, std::string dataLen);
    void approvePermissionReq(SOCKET client_sock, std::string username, std::string filename);
    void rejectPermissionReq(SOCKET client_sock, std::string username, std::string filename);
    void permissionFileReq(SOCKET client_sock, std::string username, std::string filename, std::string fileNameLen);

};
