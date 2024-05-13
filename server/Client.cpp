#include "Client.h"

ClientHandler::ClientHandler(int clientId, std::string userName, std::string email)
    : _id(clientId), _userName(userName), _email(email)
{
    file_name = "";
}  // Initialize the id field with the provided client ID

ClientHandler::ClientHandler()
{
}

ClientHandler::~ClientHandler()
{
}

int ClientHandler::getId() const {
    return _id;
}

std::string ClientHandler::getFileName() const
{
    return file_name;
}

std::string ClientHandler::getUsername() const
{
    return _userName;
}

std::string ClientHandler::getPass() const
{
    return _pass;
}

std::string ClientHandler::getEmail() const
{
    return _email;
}

void ClientHandler::setFileName(const std::string newName)
{
    file_name = newName;
}

void ClientHandler::setUsername(const std::string newName)
{
    _userName = newName;
}

void ClientHandler::setEmail(const std::string newName)
{
    _email = newName;
}

void ClientHandler::setPass(const std::string newName)
{
    _pass = newName;
}

void ClientHandler::setId(const int id)
{
    _id = id;
}