#pragma once
#include <string>
#include "sqlite3.h"
#include <io.h>
#include <list>
#include <vector>
#include "Client.h"

struct Chat
{
	std::string fileName;
	std::string data;
};

struct PermissionReq
{
	int fileId;
	int userId;
	int creatorId;
};

struct Permission
{
	int fileId;
};

struct FileDetail
{
	int creatorId;
	int fileId;
	std::string fileName;
};

class IDatabase
{
public:
	virtual ~IDatabase() = default;
	virtual bool open() = 0;
	virtual bool close() = 0;
	virtual bool doesUserExist(std::string username) = 0;
	virtual bool doesPermissionRequestExist(int userId, int fileId, int creatorId) = 0;
	virtual bool doesPasswordMatch(std::string username, std::string password) = 0;
	virtual bool hasPermission(int userId, int fileId) = 0;

	virtual bool addNewUser(std::string username, std::string password, std::string email) = 0;
	virtual int getUserId(std::string username) = 0;
	virtual std::string getUserName(std::string username, int id) = 0;
	virtual std::string getEmail(std::string username) = 0;
	virtual std::list<ClientHandler> getAllUsers() = 0;
	virtual std::string GetChatData(const std::string& fileName) = 0;
	virtual std::list<Permission> getUserPermissions(int userId) = 0;
	virtual std::list<PermissionReq> getPermissionRequests(int userId) = 0;
	virtual std::string getFileName(const int fileId) = 0;
	virtual FileDetail getFileDetails(const std::string& fileName) = 0;

	virtual void UpdateChat(const std::string& fileName, const std::string& data) = 0;
	virtual void createChat(const std::string& fileName) = 0;
	virtual void DeleteChat(const std::string& fileName) = 0;
	virtual void addPermissionRequest(int userId, int fileId, int creatorId) = 0;
	virtual void addUserPermission(int userId, int fileId) = 0;
	virtual void addFile(int userId, const std::string& fileName) = 0;
	virtual void deleteFile(const std::string& fileName) = 0;
	virtual void deletePermissionRequests(int userId, int fileId) = 0;
	virtual void deletePermission(int fileId) = 0;
	virtual void deleteAllPermissionReq(int fileId) = 0;
	virtual void changePassword(std::string username, std::string opdPass, std::string newPass) = 0;
};