#pragma once

#include <WinSock2.h>
#include <Windows.h>
#include <ws2tcpip.h>
#include <winhttp.h>

class WSAInitializer
{
public:
	WSAInitializer();
	~WSAInitializer();
};

