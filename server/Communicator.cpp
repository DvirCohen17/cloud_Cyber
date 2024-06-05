#include "Communicator.h"
#include <cstdio> // For popen and pclose


extern std::unordered_map<std::string, std::mutex> m_fileMutexes;

std::string Communicator::executeCommand(const std::string& command) {
	std::string result;
	FILE* pipe = _popen(command.c_str(), "r");
	if (!pipe) throw std::runtime_error("popen() failed!");
	char buffer[128];
	while (!feof(pipe)) {
		if (fgets(buffer, 128, pipe) != nullptr)
			result += buffer;
	}
	_pclose(pipe);
	return result;
}

Communicator::Communicator()
{
	// this server use TCP. that why SOCK_STREAM & IPPROTO_TCP
	// if the server use UDP we will use: SOCK_DGRAM & IPPROTO_UDP
	m_serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (m_serverSocket == INVALID_SOCKET)
		throw std::exception("Failed to initialize server socket.");

	std::string dirName = "files";
	std::filesystem::path dirPath = std::filesystem::current_path() / dirName;

	try {
		if (std::filesystem::create_directory(dirPath)) {
			std::cout << "Directory created successfully." << std::endl;
		}
		else {
			std::cerr << "Failed to create directory!" << std::endl;
		}
	}
	catch (const std::exception& ex) {
		std::cerr << "An error occurred: " << ex.what() << std::endl;
	}
}

// Destructor
Communicator::~Communicator() {
	try {
		closesocket(m_serverSocket);
	}
	catch (...) {}
}

void Communicator::setDB(IDatabase* db)
{
	m_database = db;
}

void Communicator::bindAndListen()
{
	struct sockaddr_in sa = { 0 };

	sa.sin_port = htons(PORT); // port that server will listen for
	sa.sin_family = AF_INET;   // must be AF_INET
	sa.sin_addr.s_addr = INADDR_ANY;    // when there are few ip's for the machine. We will use always "INADDR_ANY"

	// Connects between the socket and the configuration (port and etc..)
	if (bind(m_serverSocket, (struct sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR)
		throw std::exception("Failed to bind onto the requested port");

	// Start listening for incoming requests of clients
	if (listen(m_serverSocket, SOMAXCONN) == SOCKET_ERROR)
		throw std::exception("Failed listening to requests.");
}

void Communicator::login(SOCKET client_sock,
	std::string username, std::string pass, std::string mail)
{
	bool check = false;
	for (auto it = m_clients.begin(); it != m_clients.end(); ++it)
	{
		if (it->second->getUsername() == username || it->second->getEmail() == mail)
		{
			throw std::exception("User already logged in");
			check = true;  // Indicate that the response has been sent
			break;  // Exit the loop
		}
	}

	// If the response has been sent, don't proceed to the second condition
	if (!check)
	{
		if (m_database->doesUserExist(username) && m_database->doesPasswordMatch(username, pass))
		{
			std::string repCode = std::to_string(MC_LOGIN_RESP);
			username = m_database->getUserName(mail, -1);
			mail = m_database->getEmail(username);
			ClientHandler* client_handler = new ClientHandler(m_database->getUserId(username), username, mail);
			m_clients[client_sock] = client_handler;

			std::string lengthString = std::to_string(username.length());
			lengthString = std::string(5 - lengthString.length(), '0') + lengthString;
			repCode += lengthString + username + std::to_string(client_handler->getId());

			Helper::sendData(client_sock, BUFFER(repCode.begin(), repCode.end()));

			repCode = std::to_string(MC_LOGIN_RESP) + username;
			notifyAllClients(repCode, client_sock, false);
		}
		else
		{
			throw std::exception("invalid username or password.");
		}
	}
}

void Communicator::logout(SOCKET client_sock)
{
	std::string repCode = std::to_string(MC_LOGOUT_RESP);
	Helper::sendData(client_sock, BUFFER(repCode.begin(), repCode.end()));
	handleClientDisconnect(client_sock);
}

void Communicator::signUp(SOCKET client_sock, 
	std::string username, std::string pass, std::string mail)
{
	if (!m_database->doesUserExist(username) && !m_database->doesUserExist(mail))
	{
		m_database->addNewUser(username, pass, mail);
		std::string repCode = std::to_string(MC_SIGNUP_RESP);
		ClientHandler* client_handler = new ClientHandler(m_database->getUserId(username), username, mail);
		m_clients[client_sock] = client_handler;
		std::string initialFileContent = repCode + std::to_string(client_handler->getId());
		Helper::sendData(client_sock, BUFFER(initialFileContent.begin(), initialFileContent.end()));

		repCode += username;
		notifyAllClients(repCode, client_sock, false);
	}
	else
	{
		throw std::exception("Invalid name or email");
	}
}

void Communicator::forgotPassword(SOCKET client_sock,
	std::string username, std::string pass, std::string oldPass, std::string mail)
{
	bool check = false;
	for (auto it = m_clients.begin(); it != m_clients.end(); ++it)
	{
		if (it->second->getUsername() == username || it->second->getEmail() == mail)
		{
			throw std::exception("User logged in, cant change password");
			check = true;  // Indicate that the response has been sent
			break;  // Exit the loop
		}
	}

	// If the response has been sent, don't proceed to the second condition
	if (!check)
	{
		if (m_database->doesUserExist(username) && m_database->doesPasswordMatch(username, oldPass))
		{
			std::string repCode = std::to_string(MC_FORGOT_PASSW_RESP);
			username = m_database->getUserName(mail, -1);
			mail = m_database->getEmail(username);
			m_database->changePassword(username, oldPass, pass);
			ClientHandler* client_handler = new ClientHandler(m_database->getUserId(username), username, mail);
			m_clients[client_sock] = client_handler;

			std::string lengthString = std::to_string(username.length());
			lengthString = std::string(5 - lengthString.length(), '0') + lengthString;
			repCode += lengthString + username + std::to_string(client_handler->getId());

			Helper::sendData(client_sock, BUFFER(repCode.begin(), repCode.end()));

			repCode = std::to_string(MC_LOGIN_RESP) + username;
			notifyAllClients(repCode, client_sock, false);
		}
		else
		{
			throw std::exception("invalid username or password.");
		}
	}
}

void Communicator::createFile(SOCKET client_sock, std::string fileName)
{
	// Check if the file with the specified name exists
	//if (fileOperationHandler.fileExists(".\\files\\" + reqDetail.data + ".txt"))
	if (m_database->getFileDetails(fileName + ".txt").fileName != "")
	{
		// File already exists, send an appropriate response code
		throw std::exception("file already exists");
	}
	else
	{
		// File doesn't exist, create it and send a success response code
		std::string repCode = std::to_string(MC_APPROVE_REQ_RESP);
		Helper::sendData(client_sock, BUFFER(repCode.begin(), repCode.end()));

		fileOperationHandler.createFile(".\\files\\" + fileName + ".txt", true); // decide if needs to be removed later

		Action emptyAction;
		// Create the mutex for the new file
		m_fileMutexes[".\\files\\" + fileName + ".txt"];
		m_database->createChat(fileName);
		m_database->addFile(m_clients[client_sock]->getId(), fileName + ".txt");

		FileDetail fileList = m_database->getFileDetails(fileName + ".txt");
		m_fileNames[fileName + ".txt"] = fileList.fileId;

		m_database->addUserPermission(m_clients[client_sock]->getId(), m_fileNames[fileName + ".txt"]);

		repCode = std::to_string(MC_ADD_FILE_RESP) + fileName + ".txt";
		m_clients[client_sock]->setFileName(".\\files\\" + fileName + ".txt");

		notifyAllClients(repCode, client_sock, false);

		emptyAction.code = MC_CREATE_FILE_REQUEST;
		m_lastActionMap[".\\files\\" + fileName + ".txt"].push_back(emptyAction);
		m_usersOnFile[".\\files\\" + fileName + ".txt"].push_back(*m_clients[client_sock]);

		repCode = std::to_string(MC_JOIN_FILE_RESP);

		std::string lengthString = std::to_string((m_clients[client_sock]->getUsername().length()));
		lengthString = std::string(5 - lengthString.length(), '0') + lengthString;
		repCode += lengthString + m_clients[client_sock]->getUsername();

		fileName += ".txt";
		lengthString = std::to_string((fileName.length()));
		lengthString = std::string(5 - lengthString.length(), '0') + lengthString;
		repCode += lengthString + fileName;

		notifyAllClients(repCode, client_sock, false);

	}
}

void Communicator::deleteFile(SOCKET client_sock, std::string fileName)
{
	if (m_usersOnFile.find(".\\files\\" + fileName + ".txt") != m_usersOnFile.end()
		&& !m_usersOnFile[".\\files\\" + fileName + ".txt"].empty())
	{
		throw std::exception("cannot delete. Someone is inside");
	}
	else if (!m_database->hasPermission(m_clients[client_sock]->getId(), m_database->getFileDetails(fileName + ".txt").fileId))
	{
		throw std::exception("dont have permission for this file");
	}
	else
	{
		std::string repCode = std::to_string(MC_DELETE_FILE_RESP) + fileName + ".txt";

		fileOperationHandler.deleteFile(".\\files\\" + fileName + ".txt"); // decide if needs to be removed later

		m_database->DeleteChat(fileName);
		m_database->deleteFile(fileName + ".txt");
		m_database->deletePermission(m_fileNames[fileName + ".txt"]);
		m_database->deleteAllPermissionReq(m_fileNames[fileName + ".txt"]);
		m_fileNames.erase(fileName + ".txt");

		Helper::sendData(client_sock, BUFFER(repCode.begin(), repCode.end()));
		notifyAllClients(repCode, client_sock, false);
		Helper::sendData(client_sock, BUFFER(repCode.begin(), repCode.end()));
	}
}

void Communicator::getFiles(SOCKET client_sock)
{
	std::string repCode = std::to_string(MC_GET_FILES_RESP);

	fileOperationHandler.getFilesInDirectory(".\\files", m_fileNames);

	for (const auto& fileName : m_fileNames)
	{
		std::string lengthString = std::to_string(fileName.first.length());
		lengthString = std::string(5 - lengthString.length(), '0') + lengthString;
		repCode += lengthString + fileName.first;

		FileDetail fileList = m_database->getFileDetails(fileName.first);
		m_fileNames[fileName.first] = fileList.fileId;
	}
	Helper::sendData(client_sock, BUFFER(repCode.begin(), repCode.end()));
}

void Communicator::getInitialContent(SOCKET client_sock, std::string fileName)
{
	std::string repCode = std::to_string(MC_GET_FILES_RESP);

	std::string fileContent;
	Action emptyAction;

	repCode = std::to_string(MC_INITIAL_RESP);

	fileContent = fileOperationHandler.readFromFile(".\\files\\" + fileName);
	m_filesData[".\\files\\" + fileName] = fileContent;

	m_FileUpdate[".\\files\\" + fileName] = false;
	// Convert the length to a string with exactly 5 digits
	std::string lengthString = std::to_string(fileContent.length());
	lengthString = std::string(5 - lengthString.length(), '0') + lengthString;

	emptyAction.code = MC_INITIAL_REQUEST;
	m_lastActionMap[".\\files\\" + fileName].push_back(emptyAction);

	// Create the initialFileContent string
	std::string initialFileContent = repCode + lengthString + fileContent;
	Helper::sendData(client_sock, BUFFER(initialFileContent.begin(), initialFileContent.end()));

}

void Communicator::joinFile(SOCKET client_sock, std::string fileName, std::string fileNameLen)
{
	int fileId = m_database->getFileDetails(fileName).fileId;
	std::string repCode;

	if (!m_database->hasPermission(m_clients[client_sock]->getId(), m_database->getFileDetails(fileName).fileId)) {
		// Send an error response indicating lack of permission
		std::string errMsg = "You are not allowed to join this file" + fileNameLen+ fileName;
		throw std::exception(errMsg.c_str());
	}

	std::string lengthString = std::to_string((fileName.length()));
	lengthString = std::string(5 - lengthString.length(), '0') + lengthString;
	repCode = std::to_string(MC_APPROVE_JOIN_RESP) + lengthString + fileName;
	Helper::sendData(client_sock, BUFFER(repCode.begin(), repCode.end()));

	repCode = std::to_string(MC_JOIN_FILE_RESP);
	m_clients[client_sock]->setFileName(".\\files\\" + fileName);

	// Create the mutex for the file if it doesn't exist
	m_fileMutexes.try_emplace(".\\files\\" + fileName);

	m_usersOnFile[".\\files\\" + fileName].push_back(*m_clients[client_sock]);

	lengthString = std::to_string((m_clients[client_sock]->getUsername().length()));
	lengthString = std::string(5 - lengthString.length(), '0') + lengthString;
	repCode += lengthString + m_clients[client_sock]->getUsername();

	lengthString = std::to_string((fileName.length()));
	lengthString = std::string(5 - lengthString.length(), '0') + lengthString;
	repCode += lengthString + fileName;

	notifyAllClients(repCode, client_sock, true);
	notifyAllClients(repCode, client_sock, false);
}

void Communicator::leaveFile(SOCKET client_sock)
{
	std::string repCode = std::to_string(MC_APPROVE_REQ_RESP);
	Helper::sendData(client_sock, BUFFER(repCode.begin(), repCode.end()));

	repCode = std::to_string(MC_LEAVE_FILE_RESP);
	std::string fileName = m_clients[client_sock]->getFileName();

	for (auto it = m_usersOnFile.begin(); it != m_usersOnFile.end(); ++it) {
		// Iterate over the array of clients for each file
		for (auto clientIt = it->second.begin(); clientIt != it->second.end(); ) {
			if (clientIt->getId() == m_clients[client_sock]->getId()) {
				clientIt = it->second.erase(clientIt);
			}
			else {
				++clientIt;
			}
		}
	}

	std::string lengthString = std::to_string((m_clients[client_sock]->getUsername().length()));
	lengthString = std::string(5 - lengthString.length(), '0') + lengthString;
	repCode += lengthString + m_clients[client_sock]->getUsername();

	lengthString = std::to_string((fileName.length()));
	lengthString = std::string(5 - lengthString.length(), '0') + lengthString;
	repCode += lengthString + fileName;

	notifyAllClients(repCode, client_sock, true);
	notifyAllClients(repCode, client_sock, false);

	// Check if the user leaving was the last one
	if (m_usersOnFile[fileName].empty()) {
		// Delete the mutex and remove the file from m_usersOnFile
		m_fileMutexes.erase(fileName);
		m_usersOnFile.erase(fileName);
		m_lastActionMap.erase(fileName);
	}
	m_clients[client_sock]->setFileName("");
}

void Communicator::getMesegges(SOCKET client_sock, std::string fileName)
{
	std::string repCode = std::to_string(MC_GET_FILES_RESP);

	// Handle get messages request
	repCode = std::to_string(MC_GET_MESSAGES_RESP);
	std::string chatContent = executeCommand("main.exe decrypt \'" + m_database->GetChatData(fileName) + "\'");
	chatContent = chatContent.substr(0, chatContent.length() - 1);
	repCode += chatContent;
	Helper::sendData(client_sock, BUFFER(repCode.begin(), repCode.end()));
}

void Communicator::getUsersOnFile(SOCKET client_sock, std::string fileName)
{
	std::string repCode = std::to_string(MC_GET_USERS_ON_FILE_RESP);
	std::string lengthString;

	// Get the list of users logged into the file
	for (const auto& user : m_usersOnFile[".\\files\\" + fileName]) {
		lengthString = std::to_string((user.getUsername().length()));
		lengthString = std::string(5 - lengthString.length(), '0') + lengthString;
		repCode += lengthString + user.getUsername();
	}
	Helper::sendData(client_sock, BUFFER(repCode.begin(), repCode.end()));
}

void Communicator::getUsers(SOCKET client_sock)
{
	// Handle get users request
	std::string repCode = std::to_string(MC_GET_USERS_RESP);
	std::string lengthString;
	for (auto& sock : m_clients)
	{
		lengthString = std::to_string(m_clients[sock.first]->getUsername().length());
		lengthString = std::string(5 - lengthString.length(), '0') + lengthString;
		repCode += lengthString + m_clients[sock.first]->getUsername();

		// Add file name length and file name to the response
		lengthString = std::to_string(m_clients[sock.first]->getFileName().length());
		lengthString = std::string(5 - lengthString.length(), '0') + lengthString;
		repCode += lengthString + m_clients[sock.first]->getFileName();
	}
	Helper::sendData(client_sock, BUFFER(repCode.begin(), repCode.end()));
}

void Communicator::getUserPermissionReq(SOCKET client_sock)
{
	// Handle get users request
	std::string repCode = std::to_string(MC_APPROVE_REQ_RESP);
	Helper::sendData(client_sock, BUFFER(repCode.begin(), repCode.end()));

	repCode = std::to_string(MC_GET_USERS_PERMISSIONS_REQ_RESP);
	std::string lengthString;
	for (auto& req : m_database->getPermissionRequests(m_clients[client_sock]->getId()))
	{
		lengthString = std::to_string(m_database->getUserName("", req.userId).length());
		lengthString = std::string(5 - lengthString.length(), '0') + lengthString;
		repCode += lengthString + m_database->getUserName("", req.userId);

		// Add file name length and file name to the response
		lengthString = std::to_string(m_database->getFileName(req.fileId).length());
		lengthString = std::string(5 - lengthString.length(), '0') + lengthString;
		repCode += lengthString + m_database->getFileName(req.fileId);
	}
	Helper::sendData(client_sock, BUFFER(repCode.begin(), repCode.end()));
}

void Communicator::postMsg(SOCKET client_sock, std::string fileName, std::string data, std::string dataLen)
{
	std::string repCode = std::to_string(MC_POST_MSG_RESP);

	// Handle post message request
	std::string lengthString = std::to_string(m_clients[client_sock]->getUsername().length());
	lengthString = std::string(5 - lengthString.length(), '0') + lengthString;

	std::string chatMsg = executeCommand("main.exe decrypt \'" + m_database->GetChatData(fileName) + "\'");
	chatMsg = chatMsg.substr(0, chatMsg.length() - 1);
	chatMsg += dataLen + data +
		lengthString + m_clients[client_sock]->getUsername();
	m_database->UpdateChat(fileName, executeCommand("main.exe encrypt \'" + chatMsg + "\'"));

	repCode += dataLen + data +
		lengthString + m_clients[client_sock]->getUsername();;
	notifyAllClients(repCode, client_sock, true);
}

void Communicator::approvePermissionReq(SOCKET client_sock, std::string username, std::string filename)
{	std::string repCode = std::to_string(MC_APPROVE_PERMISSION_RESP);

	m_database->deletePermissionRequests(m_database->getUserId(username),
		m_database->getFileDetails(filename).fileId);
	m_database->addUserPermission(m_database->getUserId(username),
		m_database->getFileDetails(filename).fileId);
	Helper::sendData(client_sock, BUFFER(repCode.begin(), repCode.end()));
}

void Communicator::rejectPermissionReq(SOCKET client_sock, std::string username, std::string filename)
{
	std::string repCode = std::to_string(MC_REJECT_PERMISSION_RESP);

	m_database->deletePermissionRequests(m_database->getUserId(username), m_database->getFileDetails(filename).fileId);
	Helper::sendData(client_sock, BUFFER(repCode.begin(), repCode.end()));
}

void Communicator::permissionFileReq(SOCKET client_sock, std::string username, 
	std::string filename, std::string fileNameLen)
{
	std::string repCode;

	FileDetail fileList = m_database->getFileDetails(filename);
	if (!m_database->doesPermissionRequestExist(m_database->getUserId(username), fileList.fileId, fileList.creatorId))
	{
		repCode = std::to_string(MC_PERMISSION_FILE_REQ_RESP);
		m_database->addPermissionRequest(m_database->getUserId(username), fileList.fileId, fileList.creatorId);
		repCode += fileNameLen + filename;
	}
	else
	{
		repCode = std::to_string(MC_ERROR_RESP) + "Request already exist, waiting for the owner of the file to approve";
	}
	Helper::sendData(client_sock, BUFFER(repCode.begin(), repCode.end()));
}

void Communicator::handleNewClient(SOCKET client_sock)
{
	bool run = true;
	bool pass = true;
	std::string msg;
	std::string repCode;
	FileDetail fileList;
	BUFFER buf;

	fileOperationHandler.getFilesInDirectory(".\\files", m_fileNames);
	for (const auto& fileName : m_fileNames) 
	{
		fileList = m_database->getFileDetails(fileName.first);
		m_fileNames[fileName.first] = fileList.fileId;
	}

	while (run)
	{
		try
		{
			buf = Helper::getPartFromSocket(client_sock, 1024);
			if (buf.size() == 0)
			{
				closesocket(client_sock);
				run = false;
				// Handle disconnection
				handleClientDisconnect(client_sock);
				continue;
			}

			std::string newRequest(buf.begin(), buf.end());
			Action reqDetail = deconstructReq(newRequest);
			int msgCode = std::stoi(newRequest.substr(0, 3));
			pass = false;
			switch (msgCode)
			{
			case MC_INSERT_REQUEST:
				pass = true;
				repCode = std::to_string(MC_INSERT_RESP);
				break;
			case MC_DELETE_REQUEST:
				pass = true;
				repCode = std::to_string(MC_DELETE_RESP);
				break;
			case MC_REPLACE_REQUEST:
				pass = true;
				repCode = std::to_string(MC_REPLACE_RESP);
				break;
			case MC_LOGIN_REQUEST:
				login(client_sock, reqDetail.userName, reqDetail.pass, reqDetail.email);
				break;
			case MC_LOGOUT_REQUEST:
				logout(client_sock);
				break;
			case MC_SIGNUP_REQUEST:
				signUp(client_sock, reqDetail.userName, reqDetail.pass, reqDetail.email);
				break;
			case MC_FORGOT_PASSW_REQUEST:
				forgotPassword(client_sock, reqDetail.userName, reqDetail.pass, reqDetail.oldPass, reqDetail.email);
				break;
			case MC_INITIAL_REQUEST:
				getInitialContent(client_sock, reqDetail.data);
				break;
			case MC_CREATE_FILE_REQUEST:
				createFile(client_sock, reqDetail.data);
				break;
			case MC_DELETE_FILE_REQUEST:
				deleteFile(client_sock, reqDetail.data);
				break;
			case MC_GET_FILES_REQUEST:
				getFiles(client_sock);
				break;
			case MC_GET_MESSAGES_REQUEST:
				getMesegges(client_sock, reqDetail.data);
				break;
			case MC_GET_USERS_ON_FILE_REQUEST:
				getUsersOnFile(client_sock, reqDetail.data);
				break;
			case MC_GET_USERS_REQUEST:
				getUsers(client_sock);
				break;
			case MC_GET_USERS_PERMISSIONS_REQ_REQUEST:
				getUserPermissionReq(client_sock);
				break;
			case MC_POST_MSG_REQUEST:
				postMsg(client_sock, reqDetail.fileName, reqDetail.data, reqDetail.dataLength);
				break;
			case MC_APPROVE_PERMISSION_REQUEST:
				approvePermissionReq(client_sock, reqDetail.userName, reqDetail.fileName);
				break;
			case MC_REJECT_PERMISSION_REQUEST:
				rejectPermissionReq(client_sock, reqDetail.userName, reqDetail.fileName);
				break;
			case MC_PERMISSION_FILE_REQ_REQUEST:
				permissionFileReq(client_sock, reqDetail.userName, reqDetail.fileName, reqDetail.fileNameLength);
				break;
			case MC_JOIN_FILE_REQUEST:
				joinFile(client_sock, reqDetail.data, reqDetail.dataLength);
				break;
			case MC_LEAVE_FILE_REQUEST:
				leaveFile(client_sock);
				break;
			case MC_DISCONNECT: // Handle disconnect request
				run = false;
				handleClientDisconnect(client_sock);
				continue;
			default:
				// Handle the default case or throw an error
				throw std::runtime_error("Unknown action code: " + reqDetail.msg);
			}

			if (pass)
			{
				{
					std::string fileName = m_clients[client_sock]->getFileName();
					// Lock the mutex before updating the file
					std::lock_guard<std::mutex> lock(m_fileMutexes[fileName]);

					reqDetail = adjustIndexForSync(fileName, reqDetail);
					reqDetail.fileName = fileName;

					updateFileOnServer(fileName, reqDetail);
					notifyAllClients(repCode + reqDetail.msg, client_sock, true);
					
					reqDetail.timestamp = getCurrentTimestamp();
					m_lastActionMap[fileName].push_back(reqDetail);
					m_FileUpdate[fileName] = true;
				}// lock goes out of scope, releasing the lock
			}
		}
		catch (const std::exception& e)
		{
			// Check if it's a connection error
			if (Helper::IsConnectionError(e))
			{
				run = false;
				// Handle connection error
				handleClientDisconnect(client_sock);
			}
			else
			{
				handleError(client_sock, e);
			}
		}
	}
	closesocket(client_sock);
}

Action Communicator::adjustIndexForSync(const std::string& fileName, Action reqDetail)
{
	std::string lengthString;
	std::string selectionLengthString;
	std::string indexString;

	int selectionLength;
	int length;
	std::string data;
	int newIndex;

	int newCode = reqDetail.code;
	// Check if there is a last action recorded for this file
	if (m_lastActionMap.find(fileName) != m_lastActionMap.end())
	{
		std::vector<Action>& lastActions = m_lastActionMap[fileName];

		// Use an iterator to iterate over the vector
		auto it = lastActions.begin();

		// Iterate over all last actions for the file
		while (it != lastActions.end())
		{
			const Action& action = *it;

			// Check if the new action was created before the current last action and by a different user
			if (reqDetail.timestamp < action.timestamp && reqDetail.userId != action.userId
				&& action.code != MC_INITIAL_REQUEST && action.code != MC_CREATE_FILE_REQUEST)
			{
				int lastActionCode = action.code;
				int size = action.size;
				int lastIndex = std::stoi(action.index);

				std::string newAction = reqDetail.msg;

				std::string adjustedIndex = reqDetail.index;
				std::string updatedAction = newAction;

				newIndex = std::stoi(reqDetail.index);

				//reqDetail.timestamp = getCurrentTimestamp();

				// uodate the index
				switch (lastActionCode) {
				case MC_INSERT_REQUEST:
					if (newIndex > lastIndex)
					{
						newIndex += size;
						adjustedIndex = std::to_string(newIndex);
						adjustedIndex = std::string(5 - adjustedIndex.length(), '0') + adjustedIndex;
						updatedAction = reqDetail.dataLength + reqDetail.data + adjustedIndex;
					}
					break;
				case MC_DELETE_REQUEST:
					if (newIndex > lastIndex)
					{
						newIndex -= size;
						adjustedIndex = std::to_string(newIndex);
						adjustedIndex = std::string(5 - adjustedIndex.length(), '0') + adjustedIndex;
						updatedAction = reqDetail.dataLength + adjustedIndex;
					}
					break;
				case MC_REPLACE_REQUEST:
					if (newIndex > lastIndex)
					{
						newIndex = newIndex - std::stoi(reqDetail.selectionLength) + std::stoi(reqDetail.dataLength);
						adjustedIndex = std::to_string(newIndex);
						adjustedIndex = std::string(5 - adjustedIndex.length(), '0') + adjustedIndex;
						updatedAction = reqDetail.selectionLength + reqDetail.dataLength + reqDetail.data + adjustedIndex;
					}
					break;
				}
				reqDetail.index = adjustedIndex;
				reqDetail.msg = updatedAction;
			}
			else if (reqDetail.timestamp > action.timestamp + 5)
			{
				it = lastActions.erase(it);
			}
			if (!lastActions.empty())
			{
				++it;
			}
		}
	}
	return reqDetail;

}

void Communicator::handleError(SOCKET client_sock, std::exception a)
{
	try
	{
		// Check if the client is associated with a file
		if (m_clients.find(client_sock) != m_clients.end())
		{
			ClientHandler* client = m_clients[client_sock];

			// Check if the client is currently working on a file
			if (!client->getFileName().empty())
			{
				// Notify the client about the error
				std::string response = std::to_string(MC_ERROR_RESP);

				std::string fileContent = fileOperationHandler.readFromFile(".\\files\\" + client->getFileName());
				std::string lengthString = std::to_string(fileContent.length());
				lengthString = std::string(5 - lengthString.length(), '0') + lengthString;

				response += lengthString + fileContent;

				Helper::sendData(client_sock, BUFFER(response.begin(), response.end()));

				/*
				// If necessary, adjust and commit the client's request
				reqDetail = adjustIndexForSync(fileName, reqDetail);
				reqDetail.fileName = fileName;
				updateFileOnServer(fileName, reqDetail);

				// Notify all clients about the adjusted request
				std::string repCode = std::to_string(MC_ERR_ADJUSTED_RESP);
				notifyAllClients(repCode + reqDetail.msg, client_sock, true);

				// Update the last action map
				reqDetail.timestamp = getCurrentTimestamp();
				m_lastActionMap[fileName].push_back(reqDetail);
				*/
			}
			else
			{
				std::string initialFileContent = std::to_string(MC_ERROR_RESP) + a.what();
				Helper::sendData(client_sock, BUFFER(initialFileContent.begin(), initialFileContent.end()));
			}
		}
		else
		{
			std::string initialFileContent = std::to_string(MC_ERROR_RESP) + a.what();
			Helper::sendData(client_sock, BUFFER(initialFileContent.begin(), initialFileContent.end()));
		}
	}
	catch (const std::exception& e)
	{
	}
}

void Communicator::handleClientDisconnect(SOCKET client_sock)
{
	// Check if the client is associated with a file
	if (m_clients.find(client_sock) != m_clients.end())
	{
		ClientHandler* disconnectedClient = m_clients[client_sock];
		std::string repCode = std::to_string(MC_DISCONNECT) + disconnectedClient->getUsername();

		// Check if the client is inside a file
		if (disconnectedClient->getFileName() != "")
		{
			std::string fileName = disconnectedClient->getFileName();

			// Remove the client from the file's user list
			auto it = m_usersOnFile.find(fileName);
			if (it != m_usersOnFile.end())
			{
				it->second.erase(std::remove_if(it->second.begin(), it->second.end(),
					[disconnectedClient](const ClientHandler& client) {
						return client.getId() == disconnectedClient->getId();
					}), it->second.end());

				if (!it->second.empty()) {
					notifyAllClients(repCode, client_sock, true);
				}

				if (m_usersOnFile[fileName].empty()) {
					// Delete the mutex and remove the file from m_usersOnFile
					m_fileMutexes.erase(fileName);
					m_usersOnFile.erase(fileName);
					m_lastActionMap.erase(fileName);
				}
			}
		}
		notifyAllClients(repCode, client_sock, false);

		// Clean up resources and remove the client from the map
		delete disconnectedClient;
		m_clients.erase(client_sock);
	}
}

Action Communicator::deconstructReq(const std::string& req) {
	std::string msgCode = req.substr(0, 3);
	std::string action = req.substr(3);

	Action newAction;
	std::string indexString;

	switch (std::stoi(msgCode))
	{
	case MC_INITIAL_REQUEST:
		newAction.data = action;
		break;
	case MC_INSERT_REQUEST:
		newAction.dataLength = action.substr(0, 5);
		newAction.size = std::stoi(newAction.dataLength);

		newAction.data = action.substr(5, newAction.size);
		newAction.index = action.substr(5 + newAction.size, 5);
		newAction.newLineCount = action.substr(10 + newAction.size, 5);
		newAction.size += std::stoi(newAction.newLineCount);
		break;

	case MC_DELETE_REQUEST:
		newAction.dataLength = action.substr(0, 5);
		indexString = action.substr(5, 5);

		newAction.size = std::stoi(newAction.dataLength);
		newAction.index = indexString;
		newAction.newLineCount = action.substr(10, 5);
		break;

	case MC_REPLACE_REQUEST:
		newAction.selectionLength = action.substr(0, 5);
		newAction.dataLength = action.substr(5, 5);
		newAction.size = std::stoi(newAction.dataLength);
		newAction.data = action.substr(10, newAction.size);
		indexString = action.substr(10 + newAction.size, 5);
		newAction.index = indexString;
		newAction.newLineCount = action.substr(15 + newAction.size, 5);
		break;
	case MC_CREATE_FILE_REQUEST:
		newAction.data = action;
		break;
	case MC_GET_FILES_REQUEST:
		//newAction.data = action;
		break;
	case MC_GET_MESSAGES_REQUEST:
		newAction.data = action;
		break;
	case MC_GET_USERS_ON_FILE_REQUEST:
		newAction.data = action;
		break;
	case MC_GET_USERS_REQUEST:
		newAction.data = action;
	case MC_GET_USERS_PERMISSIONS_REQ_REQUEST:
		newAction.data = action;
		break;
	case MC_POST_MSG_REQUEST:
		newAction.fileNameLength = action.substr(0, 5);
		newAction.size = std::stoi(newAction.fileNameLength);
		newAction.fileName = action.substr(5, newAction.size);
		newAction.dataLength = action.substr(5 + newAction.size, 5);
		newAction.data = action.substr(10 + newAction.size, std::stoi(newAction.dataLength));
		break;
	case MC_APPROVE_PERMISSION_REQUEST:
		newAction.fileNameLength = action.substr(0, 5);
		newAction.size = std::stoi(newAction.fileNameLength);
		newAction.fileName = action.substr(5, newAction.size);
		newAction.userNameLength = std::stoi(action.substr(5 + newAction.size, 5));
		newAction.userName = action.substr(10 + newAction.size, newAction.userNameLength);
		break;
	case MC_REJECT_PERMISSION_REQUEST:
		newAction.fileNameLength = action.substr(0, 5);
		newAction.size = std::stoi(newAction.fileNameLength);
		newAction.fileName = action.substr(5, newAction.size);
		newAction.userNameLength = std::stoi(action.substr(5 + newAction.size, 5));
		newAction.userName = action.substr(10 + newAction.size, newAction.userNameLength);
		break;
	case MC_PERMISSION_FILE_REQ_REQUEST:
		newAction.fileNameLength = action.substr(0, 5);
		newAction.size = std::stoi(newAction.fileNameLength);
		newAction.fileName = action.substr(5, newAction.size);
		newAction.userNameLength = std::stoi(action.substr(5 + newAction.size, 5));
		newAction.userName = action.substr(10 + newAction.size, newAction.userNameLength);
	case MC_JOIN_FILE_REQUEST:
		newAction.dataLength = action.substr(0, 5);
		newAction.data = action.substr(5, std::stoi(newAction.dataLength));
		break;
	case MC_LEAVE_FILE_REQUEST:
		newAction.data = action.substr(0, 5);
		break;
	case MC_DELETE_FILE_REQUEST:
		newAction.dataLength = action.substr(0, 5);
		newAction.data = action.substr(5, std::stoi(newAction.dataLength));
		break;
	case MC_LOGIN_REQUEST:
		newAction.userNameLength = std::stoi(action.substr(0, 5));
		newAction.userName = action.substr(5, newAction.userNameLength);
		newAction.email = newAction.userName;

		newAction.passLength = std::stoi(action.substr(5 + newAction.userNameLength, 5));
		newAction.pass = action.substr(10 + newAction.userNameLength, newAction.passLength);
		break;

	case MC_SIGNUP_REQUEST:
		newAction.userNameLength = std::stoi(action.substr(0, 5));
		newAction.userName = action.substr(5, newAction.userNameLength);

		newAction.passLength = std::stoi(action.substr(5 + newAction.userNameLength, 5));
		newAction.pass = action.substr(10 + newAction.userNameLength, newAction.passLength);

		newAction.emailLength = std::stoi(action.substr(10 + newAction.userNameLength + newAction.passLength, 5));
		newAction.email = action.substr(15 + newAction.userNameLength + newAction.passLength, newAction.emailLength);
		break;
	case MC_FORGOT_PASSW_REQUEST:
		newAction.userNameLength = std::stoi(action.substr(0, 5));
		newAction.userName = action.substr(5, newAction.userNameLength);
		newAction.email = newAction.userName;

		newAction.oldPassLength = std::stoi(action.substr(5 + newAction.userNameLength, 5));
		newAction.oldPass = action.substr(10 + newAction.userNameLength, newAction.oldPassLength);

		newAction.passLength = std::stoi(action.substr(10 + newAction.userNameLength + newAction.oldPassLength, 5));
		newAction.pass = action.substr(15 + newAction.userNameLength + newAction.oldPassLength, newAction.passLength);
		break;
	}
	newAction.timestamp = getCurrentTimestamp();
	newAction.code = std::stoi(msgCode);
	newAction.msg = action;
	return newAction;
}

void Communicator::updateFileOnServer(const std::string& filePath, const Action& reqDetail)
{
	std::fstream file(filePath, std::ios::in | std::ios::out);
	if (!file.is_open()) {
		throw std::runtime_error("Failed to open file for reading/writing: " + filePath);
	}
	else {
		switch (reqDetail.code) {
		case MC_INSERT_REQUEST:
			// Insert operation
			operationHandler.insert(file, reqDetail.data, (std::stoi(reqDetail.index) + std::stoi(reqDetail.newLineCount)));
			break;

		case MC_DELETE_REQUEST:
			// Delete operation
			operationHandler.deleteContent(file, std::stoi(reqDetail.dataLength), (std::stoi(reqDetail.index) + std::stoi(reqDetail.newLineCount)),
				reqDetail.fileName);
			break;

		case MC_REPLACE_REQUEST:
			// Replace operation
			operationHandler.replace(file, std::stoi(reqDetail.selectionLength), reqDetail.data,
				(std::stoi(reqDetail.index) + std::stoi(reqDetail.newLineCount)), reqDetail.fileName);
			break;

		default:
			throw std::runtime_error("Unknown action code: " + reqDetail.code);
		}

		file.close();
	}
}

void Communicator::notifyAllClients(const std::string& updatedContent, SOCKET client_sock, const bool isOnFile)
{
	// Iterate through all connected clients and send them the updated content
	for (auto& sock : m_clients)
	{
		if (sock.first != client_sock)
		{
			if (isOnFile && m_clients[client_sock]->getFileName() == m_clients[sock.first]->getFileName())
			{
				SOCKET client_sock = sock.first;
				Helper::sendData(client_sock, BUFFER(updatedContent.begin(), updatedContent.end()));
			}
			else if (!isOnFile && m_clients[sock.first]->getFileName() == "")
			{
				SOCKET client_sock = sock.first;
				Helper::sendData(client_sock, BUFFER(updatedContent.begin(), updatedContent.end()));
			}
		}
	}
}

long long Communicator::getCurrentTimestamp() {
	auto currentTime = std::chrono::system_clock::now();
	auto duration = currentTime.time_since_epoch();

	// Convert duration to milliseconds
	auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(duration);

	// Convert milliseconds to a long long value
	return milliseconds.count();
}

void Communicator::startHandleRequests()
{
	SOCKET client_socket;
	bindAndListen();
	while (true)
	{
		client_socket = accept(m_serverSocket, NULL, NULL);
		if (client_socket == INVALID_SOCKET)
			throw std::exception("Recieved an invalid socket.");
		std::thread t(&Communicator::handleNewClient, this, client_socket);
		t.detach();
	}
}
