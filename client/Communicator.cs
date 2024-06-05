using System;
using System.IO;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using System.Security.Cryptography;

namespace client_side
{
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
    public class Communicator
    {
        private Socket m_socket;
        public int UserId { get; set; }
        public string UserName { get; set; }
        public Communicator(string ip, int port)
        {
            m_socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            if (m_socket == null)
            {
                throw new ExternalException("Socket failed to initialize");
            }

            m_socket.Connect(ip, port);

        }

        ~Communicator()
        {
            m_socket.Close();
        }

        public string HashPassword(string password)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < hashedBytes.Length; i++)
                {
                    builder.Append(hashedBytes[i].ToString("x2"));
                }
                return builder.ToString();
            }
        }

        public void SendData(string message)
        {
            //LogAction(message);
            byte[] data = Encoding.UTF8.GetBytes(message);
            m_socket.Send(data);
        }

        public string ReceiveData()
        {
            byte[] buffer = new byte[1024];  // Adjust the buffer size as needed
            int bytesRead = m_socket.Receive(buffer);
            string rep = Encoding.UTF8.GetString(buffer, 0, bytesRead);
            //LogAction(rep);
            return rep;
        }

        /*
        public string ReceiveData(CancellationToken cancellationToken)
        {
            // Adjust the timeout value as needed
            TimeSpan timeout = TimeSpan.FromSeconds(1);

            // Use CancellationTokenSource to apply timeout
            using (var timeoutCts = new CancellationTokenSource(timeout))
            using (var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token))
            {
                try
                {
                    byte[] buffer = new byte[1024];  // Adjust the buffer size as needed
                    int bytesRead = m_socket.Receive(buffer);
                    string rep = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                    LogAction(rep);
                    return rep;
                }
                catch (OperationCanceledException)
                {
                    // Handle the case where the operation is canceled due to timeout
                    throw new TimeoutException("Receive operation timed out.");
                }
                catch (Exception ex)
                {
                    // Handle other exceptions
                    throw new Exception($"Error receiving data: {ex.Message}");
                }
            }
        }

        public string ReceiveDataWithTimeout(TimeSpan timeout)
        {
            try
            {
                using (var cts = new CancellationTokenSource(timeout))
                {
                    var token = cts.Token;

                    Task<string> receiveTask = Task.Run(() =>
                    {
                        // Replace the following line with your actual ReceiveData logic
                        // Here, I'm assuming ReceiveData returns a string
                        return ReceiveData();
                    }, token);

                    // Wait for the task to complete within the specified timeout
                    if (receiveTask.Wait(timeout))
                    {
                        // Task completed within the timeout
                        return receiveTask.Result;
                    }
                    else
                    {
                        // Timeout occurred
                        return null;
                    }
                }
            }
            catch (Exception ex)
            {
                // Handle exceptions as needed
                Console.WriteLine($"Error in ReceiveDataWithTimeout: {ex.Message}");
                return null;
            }
        }

        */
        public void LogAction(string action)
        {
            try
            {
                string logFilePath = "UserLog_" + UserName + ".txt";

                // Append the action to the log file
                File.AppendAllText(logFilePath, $"{DateTime.Now}: {action}\n");
                //File.AppendAllText(logFilePath, $"{action}\n"); // - just the msg without date
            }
            catch (Exception ex)
            {
                // Handle the exception or log it to another source
                MessageBox.Show($"Error logging action: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        public bool ContainsSqlInjection(string input)
        {
            // Define a list of special characters commonly used in SQL injection
            string[] sqlSpecialCharacters = { "'", ";", "--", "/*", "*/", "xp_", "exec", "sp_"};

            // Check if the input contains any of the special characters
            foreach (var specialCharacter in sqlSpecialCharacters)
            {
                if (input.Contains(specialCharacter, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }
    }
}
