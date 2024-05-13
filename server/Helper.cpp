#include "Helper.h"


void Helper::sendData(const SOCKET sc, const BUFFER message)
{
	const char* data = message.data();

	if (send(sc, data, message.size(), 0) == INVALID_SOCKET)
	{
		throw std::exception("Error while sending message to client");
	}
}

BUFFER Helper::getPartFromSocket(const SOCKET sc, const int bytesNum)
{
	return getPartFromSocket(sc, bytesNum, 0);
}

BUFFER Helper::getPartFromSocket(const SOCKET sc, const int bytesNum, const int flags)
{
	if (bytesNum == 0)
	{
		return BUFFER();
	}

	BUFFER recieved(bytesNum);
	int bytes_recieved = recv(sc, &recieved[0], bytesNum, flags);
	if (bytes_recieved == INVALID_SOCKET)
	{
		std::string s = "Error while recieving from socket: ";
		s += std::to_string(sc);
		throw std::exception(s.c_str());
	}
	recieved.resize(bytes_recieved);
	return recieved;
}

bool Helper::IsConnectionError(const std::exception& e)
{
	// Check if the exception message contains a specific string indicating a connection error
	return (std::string(e.what()).find("Error while receiving from socket") != std::string::npos) ||
		(std::string(e.what()).find("Error while sending message to client") != std::string::npos);
}