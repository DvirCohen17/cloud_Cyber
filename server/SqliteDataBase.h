#pragma once
#include "IDatabase.h"
#include "Client.h"

class SqliteDataBase : public IDatabase
{
public:
	SqliteDataBase() = default;
	~SqliteDataBase() = default;

	bool open() override;
	bool close() override;
	bool doesUserExist(std::string username) override;
	bool doesPermissionRequestExist(int userId, int fileId, int creatorId) override;
	bool doesPasswordMatch(std::string username, std::string password) override;
	bool hasPermission(int userId, int fileId) override;

	bool addNewUser(std::string username, std::string password, std::string email) override;
	int getUserId(std::string username) override;
	std::string getUserName(std::string username, int id) override;
	std::string getEmail(std::string username) override;
	std::list<ClientHandler> getAllUsers() override;
	std::string GetChatData(const std::string& fileName) override;
	std::list<Permission> getUserPermissions(int userId) override;
	std::list<PermissionReq> getPermissionRequests(int userId) override;
	FileDetail getFileDetails(const std::string& fileName) override;
	std::string getFileName(const int fileId) override;

	void UpdateChat(const std::string& fileName, const std::string& data) override;
	void createChat(const std::string& fileName) override;
	void DeleteChat(const std::string& fileName) override;
	void addPermissionRequest(int userId, int fileId, int creatorId) override;
	void addUserPermission(int userId, int fileId) override;
	void addFile(int userId, const std::string& fileName) override;
	void deleteFile(const std::string& fileName) override;
	void deletePermissionRequests(int userId, int fileId) override;
	void deletePermission(int fileId) override;
	void deleteAllPermissionReq(int fileId) override;
	void changePassword(std::string username, std::string opdPass, std::string newPass) override;

private:
	sqlite3* _db;

	bool send(sqlite3* db, std::string msg);
	bool send_users(sqlite3* db, std::string msg, std::list<ClientHandler>* users);
	bool send_data(sqlite3* db, std::string msg, std::list<std::string>* data);
	bool send_chats(sqlite3* db, std::string msg, std::list<Chat>* data);
	bool send_Permissions(sqlite3* db, std::string msg, std::list<Permission>* data);
	bool send_PermissionReq(sqlite3* db, std::string msg, std::list<PermissionReq>* data);
	bool send_file(sqlite3* db, std::string msg, std::list<FileDetail>* data);
};

