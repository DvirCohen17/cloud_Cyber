#include "SqliteDataBase.h"

int callback_data(void* data, int argc, char** argv, char** azColName)
{
	std::list<std::string>* list_data = (std::list<std::string>*)data;

	for (int i = 0; i < argc; i++) {
		list_data->push_back(argv[i]);
	}
	return 0;
}

int callback_users(void* data, int argc, char** argv, char** azColName)
{
	std::list<ClientHandler>* list_users = (std::list<ClientHandler>*)data;
	ClientHandler user;

	for (int i = 0; i < argc; i++) {
		if (std::string(azColName[i]) == "user_name") {
			user.setUsername(argv[i]);
		}
		else if (std::string(azColName[i]) == "mail") {
			user.setEmail(argv[i]);
		}
		else if (std::string(azColName[i]) == "password") {
			user.setPass(argv[i]);
		}
		else if (std::string(azColName[i]) == "id") {
			user.setId(std::stoi(argv[i]));
		}
	}
	list_users->push_back(user);
	return 0;
}

int callback_chats(void* data, int argc, char** argv, char** azColName)
{
	std::list<Chat>* list_chats = (std::list<Chat>*)data;
	Chat chat;

	for (int i = 0; i < argc; i++) {
		if (std::string(azColName[i]) == "fileName") {
			chat.fileName = argv[i];
		}
		else if (std::string(azColName[i]) == "data") {
			chat.data = argv[i];
		}
	}
	list_chats->push_back(chat);
	return 0;
}

int callback_Permissions(void* data, int argc, char** argv, char** azColName)
{
	std::list<Permission>* list_permissions = (std::list<Permission>*)data;
	Permission perm;

	for (int i = 0; i < argc; i++) {
		if (std::string(azColName[i]) == "fileId") {
			perm.fileId = std::stoi(argv[i]);
		}
	}
	list_permissions->push_back(perm);
	return 0;
}

int callback_PermissionReq(void* data, int argc, char** argv, char** azColName)
{
	std::list<PermissionReq>* list_permissionReq = (std::list<PermissionReq>*)data;
	PermissionReq req;

	for (int i = 0; i < argc; i++) {
		if (std::string(azColName[i]) == "fileId") {
			req.fileId = std::stoi(argv[i]);
		}
		else if (std::string(azColName[i]) == "userId") {
			req.userId = std::stoi(argv[i]);
		}
		else if (std::string(azColName[i]) == "creatorId") {
			req.creatorId = std::stoi(argv[i]);
		}
	}
	list_permissionReq->push_back(req);
	return 0;
}

int callback_File(void* data, int argc, char** argv, char** azColName)
{
	std::list<FileDetail>* list_files = (std::list<FileDetail>*)data;
	FileDetail file;

	for (int i = 0; i < argc; i++) {
		if (std::string(azColName[i]) == "fileName") {
			file.fileName = argv[i];
		}
		else if (std::string(azColName[i]) == "creatorId") {
			file.creatorId = std::stoi(argv[i]);
		}
		else if (std::string(azColName[i]) == "fileId") {
			file.fileId = std::stoi(argv[i]);
		}
	}
	list_files->push_back(file);
	return 0;
}

bool SqliteDataBase::send(sqlite3* db, std::string msg)
{
	const char* sqlStatement = msg.c_str();
	char* errMessage = nullptr;
	int res = sqlite3_exec(db, sqlStatement, nullptr, nullptr, &errMessage);
	if (res != SQLITE_OK)
		return false;

	return true;
}

bool SqliteDataBase::send_users(sqlite3* db, std::string msg, std::list<ClientHandler>* users)
{
	const char* sqlStatement = msg.c_str();
	char* errMessage = nullptr;
	int res = sqlite3_exec(db, sqlStatement, callback_users, users, &errMessage);
	if (res != SQLITE_OK)
		return false;

	return true;
}

bool SqliteDataBase::send_chats(sqlite3* db, std::string msg, std::list<Chat>* chats)
{
	const char* sqlStatement = msg.c_str();
	char* errMessage = nullptr;
	int res = sqlite3_exec(db, sqlStatement, callback_chats, chats, &errMessage);
	if (res != SQLITE_OK)
		return false;

	return true;
}

bool SqliteDataBase::send_Permissions(sqlite3* db, std::string msg, std::list<Permission>* data)
{
	const char* sqlStatement = msg.c_str();
	char* errMessage = nullptr;
	int res = sqlite3_exec(db, sqlStatement, callback_Permissions, data, &errMessage);
	if (res != SQLITE_OK)
		return false;

	return true;
}

bool SqliteDataBase::send_PermissionReq(sqlite3* db, std::string msg, std::list<PermissionReq>* data)
{
	const char* sqlStatement = msg.c_str();
	char* errMessage = nullptr;
	int res = sqlite3_exec(db, sqlStatement, callback_PermissionReq, data, &errMessage);
	if (res != SQLITE_OK)
		return false;

	return true;
}

bool SqliteDataBase::send_file(sqlite3* db, std::string msg, std::list<FileDetail>* data)
{
	const char* sqlStatement = msg.c_str();
	char* errMessage = nullptr;
	int res = sqlite3_exec(db, sqlStatement, callback_File, data, &errMessage);
	if (res != SQLITE_OK)
		return false;

	return true;
}

bool SqliteDataBase::send_data(sqlite3* db, std::string msg, std::list<std::string>* data)
{
	const char* sqlStatement = msg.c_str();
	char* errMessage = nullptr;
	int res = sqlite3_exec(db, sqlStatement, callback_data, data, &errMessage);
	if (res != SQLITE_OK)
		return false;

	return true;
}


bool SqliteDataBase::open()
{
	std::string dbFileName = "syncDBTemp.sqlite";
	int file_exist = _access(dbFileName.c_str(), 0);
	int res = sqlite3_open(dbFileName.c_str(), &_db);

	if (res != SQLITE_OK) {
		_db = nullptr;
		std::cout << "Failed to open DB" << std::endl;
		return -1;
	}
	if (file_exist != 0) {
		std::string msg;

		msg = "CREATE TABLE 'users' ("
			" id INTEGER PRIMARY KEY AUTOINCREMENT,"
			" user_name TEXT UNIQUE NOT NULL,"
			" password TEXT NOT NULL,"
			" mail TEXT NOT NULL);";
		send(_db, msg);
		msg = "CREATE TABLE 'chats' ("
			" id INTEGER PRIMARY KEY AUTOINCREMENT,"
			" fileName TEXT UNIQUE NOT NULL,"
			" data TEXT NOT NULL);";
		send(_db, msg);
		msg = "CREATE TABLE Files ("
			"fileId INTEGER PRIMARY KEY AUTOINCREMENT,"
			"creatorId INTEGER,"
			"fileName TEXT,"
			"FOREIGN KEY(creatorId) REFERENCES users(id)"
			"); ";
		send(_db, msg);
		msg = "CREATE TABLE UserPermissions ("
			"id INTEGER PRIMARY KEY AUTOINCREMENT,"
			"userId INTEGER,"
			"fileId INTEGER,"
			"FOREIGN KEY(userId) REFERENCES Users(id),"
			"FOREIGN KEY(fileId) REFERENCES Files(fileId),"
			"UNIQUE(userId, fileId)"
			"); ";
		send(_db, msg);
		msg = "CREATE TABLE PermissionRequests ("
			"id INTEGER PRIMARY KEY AUTOINCREMENT,"
			"fileId INTEGER,"
			"creatorId INTEGER,"
			"userId INTEGER,"
			"FOREIGN KEY(creatorId) REFERENCES Users(id),"
			"FOREIGN KEY(fileId) REFERENCES Files(fileId),"
			"FOREIGN KEY(userId) REFERENCES Users(id)"
			"); ";
		send(_db, msg);
	}
	return true;
}

bool SqliteDataBase::close()
{
	sqlite3_close(_db);
	_db = nullptr;
	return true;
}

std::list<ClientHandler> SqliteDataBase::getAllUsers()
{
	std::string msg = "SELECT * FROM users;";
	std::list<ClientHandler> listOfUsers = {};
	send_users(_db, msg, &listOfUsers);

	return listOfUsers;
}

int SqliteDataBase::getUserId(std::string username)
{
	std::string msg = "SELECT id FROM users WHERE user_name = \'" + username + "\';";
	std::list<std::string> list_data;
	send_data(_db, msg, &list_data);
	int id;

	if (list_data.empty())
	{
		throw std::exception("Failed to find user id");
	}
	for (const auto& per : list_data)
	{
		id = atoi(per.c_str());
	}
	return id;
}

std::string SqliteDataBase::getUserName(std::string username, int id)
{
	std::list<ClientHandler> users_list = getAllUsers();

	if (!users_list.empty())
	{
		for (auto user : users_list)
		{
			if (user.getUsername() == username || user.getEmail() == username || user.getId() == id)
			{
				return user.getUsername();
			}
		}
	}
	return "";
}

std::string SqliteDataBase::getEmail(std::string username)
{
	std::list<ClientHandler> users_list = getAllUsers();

	if (!users_list.empty())
	{
		for (auto user : users_list)
		{
			if (user.getUsername() == username || user.getEmail() == username)
			{
				return user.getEmail();
			}
		}
	}
	return "";
}

bool SqliteDataBase::doesUserExist(std::string username)
{
	std::list<ClientHandler> users_list = getAllUsers();

	if (!users_list.empty())
	{
		for (auto user : users_list)
		{
			if (user.getUsername() == username || user.getEmail() == username)
			{
				return true;
			}
		}
	}
	return false;
}

bool SqliteDataBase::doesPasswordMatch(std::string username, std::string password)
{
	std::list<ClientHandler> users_list = getAllUsers();

	if (!users_list.empty())
	{
		for (auto user : users_list)
		{
			if (user.getUsername() == username && user.getPass() == password || user.getEmail() == username && user.getPass() == password)
			{
				return true;
			}
		}
	}
	return false;
}


bool SqliteDataBase::addNewUser(std::string username, std::string password, std::string email)
{
	std::string msg;

	msg = "INSERT INTO users (user_name, password, mail) "
		"VALUES (\'" + username + "\', \'" + password + "\', \'" + email + "\');";

	return send(_db, msg);
}

void SqliteDataBase::changePassword(std::string username, std::string opdPass, std::string newPass)
{
	std::string msg;
	
	msg = "UPDATE users SET password = \'" + newPass + "\' WHERE user_name = \'" + username + "\'; ";

	send(_db, msg);
}

void SqliteDataBase::UpdateChat(const std::string& fileName, const std::string& data)
{
	DeleteChat(fileName);

	std::string msg = "INSERT INTO chats (fileName, data) VALUES (\'" + fileName + "\', \"" + data + "\"); ";

	send(_db, msg);
}

void SqliteDataBase::createChat(const std::string& fileName)
{
	std::string msg;

	msg = "INSERT INTO chats (fileName, data) VALUES (\'" + fileName + "\', ''); ";

	send(_db, msg);
}

void SqliteDataBase::DeleteChat(const std::string& fileName)
{
	std::string msg;

	msg = "DELETE FROM chats WHERE fileName = \'" + fileName + "\';";

	send(_db, msg);
}

std::string SqliteDataBase::GetChatData(const std::string& fileName)
{
	std::string msg;
	std::list<Chat> chatList; // This list will store the result data

	// Assuming 'fileName' is a unique identifier in the 'chats' table

	msg = "SELECT * FROM chats WHERE fileName = \'" + fileName + "\';";

	send_chats(_db, msg, &chatList);

	for (const Chat& data : chatList) {
		if (data.fileName == fileName)
		{
			return data.data;
		}
	}
}

void SqliteDataBase::addPermissionRequest(int userId, int fileId, int creatorId) {
	std::string msg = "INSERT INTO PermissionRequests (userId, fileId, creatorId) "
		"VALUES(" + std::to_string(userId) + ", " + std::to_string(fileId) + ", " + std::to_string(creatorId) + "); ";
	send(_db, msg);
}

std::list<PermissionReq> SqliteDataBase::getPermissionRequests(int userId) {
	std::string msg = "SELECT * FROM PermissionRequests WHERE creatorId = \'" + std::to_string(userId) + "\';";

	std::list<PermissionReq> requestList;
	send_PermissionReq(_db, msg, &requestList);

	return requestList;
}

bool SqliteDataBase::doesPermissionRequestExist(int userId, int fileId, int creatorId) {
	std::string msg = "SELECT * FROM PermissionRequests WHERE userId = '" + std::to_string(userId) +
		"' AND fileId = '" + std::to_string(fileId) +
		"' AND creatorId = '" + std::to_string(creatorId) + "';";

	std::list<PermissionReq> requestList;
	send_PermissionReq(_db, msg, &requestList);

	return !requestList.empty();
}

void SqliteDataBase::addUserPermission(int userId, int fileId) {
	std::string msg = "INSERT INTO UserPermissions (userId, fileId) "
		"VALUES (" + std::to_string(userId) + "," + std::to_string(fileId) + ");";
	send(_db, msg);
}

std::list<Permission> SqliteDataBase::getUserPermissions(int userId) {
	std::string msg = "SELECT * FROM UserPermissions WHERE userId = " + std::to_string(userId) + ";";

	std::list<Permission> permissionList;
	send_Permissions(_db, msg, &permissionList);

	return permissionList;
}

bool SqliteDataBase::hasPermission(int userId, int fileId) {
	std::string msg = "SELECT * from UserPermissions WHERE userId = " + std::to_string(userId) +
		" AND fileId = " + std::to_string(fileId) + ";";

	std::list<Permission> permissionList;
	send_Permissions(_db, msg, &permissionList);
	if (!permissionList.empty())
	{
		return true;
	}
	return false;
}

void SqliteDataBase::addFile(int userId, const std::string& fileName) {
	std::string msg = "INSERT INTO Files (creatorId, fileName) "
		"VALUES (" + std::to_string(userId) + ", \'" + fileName + "\');";
	send(_db, msg);
}

void SqliteDataBase::deleteFile(const std::string& fileName) {
	std::string msg = "DELETE FROM Files WHERE fileName = \'" + fileName + "\';";
	send(_db, msg);
}

void SqliteDataBase::deletePermissionRequests(int userId, int fileId) {
	std::string msg = "DELETE FROM PermissionRequests WHERE fileId = " + std::to_string(fileId) + " AND userId = " + std::to_string(userId) + ";";
	send(_db, msg);
}

void SqliteDataBase::deleteAllPermissionReq(int fileId) {
	std::string msg = "DELETE FROM PermissionRequests WHERE fileId = " + std::to_string(fileId) + ";";
	send(_db, msg);
}

void SqliteDataBase::deletePermission(int fileId) {
	std::string msg = "DELETE FROM UserPermissions WHERE fileId = " + std::to_string(fileId) + ";";
	send(_db, msg);
}

FileDetail SqliteDataBase::getFileDetails(const std::string& fileName) {
	std::string msg = "SELECT * FROM Files WHERE fileName = \'" + fileName + "\';";

	std::list<FileDetail> fileList;
	FileDetail emptyFile;
	emptyFile.fileName = "";
	send_file(_db, msg, &fileList);

	for (const FileDetail& data : fileList) {
		if (data.fileName == fileName)
		{
			return data;
		}
	}
	return emptyFile;
}

std::string SqliteDataBase::getFileName(const int fileId)
{
	std::string msg = "SELECT * FROM Files WHERE fileId = " + std::to_string(fileId) + ";";

	std::list<FileDetail> fileList;
	send_file(_db, msg, &fileList);

	for (const FileDetail& data : fileList) {
		if (data.fileId == fileId)
		{
			return data.fileName;
		}
	}
}