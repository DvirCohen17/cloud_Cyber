#pragma once
#include <vector>
#define BUFFER std::vector<char>

#include "WSAInitializer.h"
#include <string>

enum MessageCodes
{
    MC_INITIAL_REQUEST = 101, //requests
    MC_INSERT_REQUEST = 102,
    MC_DELETE_REQUEST = 103,
    MC_REPLACE_REQUEST = 104,
    MC_CREATE_FILE_REQUEST = 105,
    MC_GET_FILES_REQUEST = 106,
    MC_CLOSE_FILE_REQUEST = 108,
    MC_GET_MESSAGES_REQUEST = 109,
    MC_GET_USERS_ON_FILE_REQUEST = 110,
    MC_POST_MSG_REQUEST = 111,
    MC_JOIN_FILE_REQUEST = 112,
    MC_LEAVE_FILE_REQUEST = 113,
    MC_DELETE_FILE_REQUEST = 114,
    MC_GET_USERS_REQUEST = 115,
    MC_GET_USERS_PERMISSIONS_REQ_REQUEST = 116,
    MC_APPROVE_PERMISSION_REQUEST = 117,
    MC_REJECT_PERMISSION_REQUEST = 118,
    MC_PERMISSION_FILE_REQ_REQUEST = 119,

    MC_ERROR_RESP = 200, //responses
    MC_INITIAL_RESP = 201,
    MC_INSERT_RESP = 202,
    MC_DELETE_RESP = 203,
    MC_REPLACE_RESP = 204,
    MC_CREATE_FILE_RESP = 205,
    MC_GET_FILES_RESP = 206,
    MC_ADD_FILE_RESP = 207,
    MC_CLOSE_FILE_RESP = 208,
    MC_GET_MESSAGES_RESP = 209,
    MC_GET_USERS_ON_FILE_RESP = 210,
    MC_POST_MSG_RESP = 211,
    MC_JOIN_FILE_RESP = 212,
    MC_LEAVE_FILE_RESP = 213,
    MC_DELETE_FILE_RESP = 214,
    MC_GET_USERS_RESP = 215,
    MC_GET_USERS_PERMISSIONS_REQ_RESP = 216,
    MC_APPROVE_PERMISSION_RESP = 217,
    MC_REJECT_PERMISSION_RESP = 218,
    MC_PERMISSION_FILE_REQ_RESP = 219,

    MC_DISCONNECT = 300, //user
    MC_LOGIN_REQUEST = 301,
    MC_LOGOUT_REQUEST = 306,
    MC_SIGNUP_REQUEST = 303,
    MC_FORGOT_PASSW_REQUEST = 304,

    MC_APPROVE_REQ_RESP = 302,
    MC_APPROVE_JOIN_RESP = 305,

    MC_LOGIN_RESP = 401,
    MC_SIGNUP_RESP = 403,
    MC_FORGOT_PASSW_RESP = 404,
    MC_LOGOUT_RESP = 406

};

class Helper
{
public:
    static void sendData(const SOCKET sc, const BUFFER message);

    static BUFFER getPartFromSocket(const SOCKET sc, const int bytesNum);
    static BUFFER getPartFromSocket(const SOCKET sc, const int bytesNum, const int flags);

    static bool IsConnectionError(const std::exception& e);
};
