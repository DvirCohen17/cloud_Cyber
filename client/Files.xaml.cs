using Microsoft.VisualBasic;
using System;
using System.Collections.Generic;
using System.IO;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using System.Windows.Threading;
using static client_side.PermissionRequestsWindow;

namespace client_side
{
    /// <summary>
    /// Interaction logic for Files.xaml
    /// </summary>
    public partial class Files : Window
    {
        Communicator communicator;
        bool disconnect = true; // if window closed by the user disconnect
        private Thread receiveServerUpdatesThread;

        private bool isListeningToServer = true;
        public Files(Communicator communicator)
        {
            InitializeComponent();
            Style = (Style)FindResource(typeof(Window));
            this.communicator = communicator;

            lstFiles.KeyDown += LstFiles_KeyDown;
            txtNewFileName.KeyDown += TxtNewFileName_KeyDown;

            start();

            receiveServerUpdatesThread = new Thread(() => ReceiveServerUpdates())
            {
                IsBackground = true
            };
            receiveServerUpdatesThread.Start();

            Closing += Files_CloseFile; // Hook up the closing event handler
        }


        private void start()
        {
            string code = ((int)MessageCodes.MC_GET_USERS_REQUEST).ToString();
            communicator.SendData($"{code}");

            string rep = communicator.ReceiveData();
            string repCode = rep.Substring(0, 3);

            if (repCode == ((int)MessageCodes.MC_GET_USERS_RESP).ToString() &&
                    rep.Length > 3)
            {
                List<string> users = new List<string>();

                int currentIndex = 3;

                // Extract each user from the response
                while (currentIndex < rep.Length)
                {
                    int nameLength = int.Parse(rep.Substring(currentIndex, 5));
                    currentIndex += 5;

                    string name = rep.Substring(currentIndex, nameLength);
                    currentIndex += nameLength;

                    int fileLength = int.Parse(rep.Substring(currentIndex, 5)) + 2;
                    currentIndex += 5;

                    string fileName;
                    if (fileLength > 2)
                    {
                        fileName = rep.Substring(currentIndex + 8, fileLength - 14);
                    }
                    else
                    {
                        fileName = rep.Substring(currentIndex, fileLength - 2);
                    }
                    currentIndex += fileLength - 2;

                    if (fileName != "")
                    {
                        users.Add(name + " - \"" + fileName + "\"");
                    }
                    else
                    {
                        users.Add(name);
                    }
                }

                // Update the user list in the UI
                UpdateUserList(users);
            }

            code = ((int)MessageCodes.MC_GET_FILES_REQUEST).ToString();
            communicator.SendData($"{code}");

            rep = communicator.ReceiveData();
            repCode = rep.Substring(0, 3);

            if (repCode == ((int)MessageCodes.MC_GET_FILES_RESP).ToString() && rep.Length > 3)
            {
                // Remove the response code from the received message
                string filesData = rep.Substring(3);
                List<FileModel> fileList = new List<FileModel>();

                int currentIndex = 0;
                // Loop through the file data array and create FileModel objects
                while (currentIndex < filesData.Length)
                {
                    // Extract data length for each message
                    int dataLength = int.Parse(filesData.Substring(currentIndex, 5));
                    currentIndex += 5;

                    // Extract data from the response
                    string data = filesData.Substring(currentIndex, dataLength);
                    currentIndex += dataLength;

                    fileList.Add(new FileModel { FileName = data });
                }

                fileList.Sort((a, b) => string.Compare(a.FileName, b.FileName, StringComparison.OrdinalIgnoreCase));

                // Use Dispatcher to update UI on the UI thread
                Dispatcher.Invoke(() =>
                {
                    // Set the ListBox's ItemsSource to the sorted list of FileModel objects
                    lstFiles.ItemsSource = fileList;
                });
            }
        }

        private void LstFiles_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                e.Handled = true;
                Join(sender, e);
            }
            if (e.Key == Key.Back)
            {
                remove(sender, e);
            }
        }

        private void lstFiles_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            e.Handled = true;
            Join(sender, e);
        }

        private void Join(object sender, RoutedEventArgs e)
        {
            FileModel selectedFile = lstFiles.SelectedItem as FileModel;
            if (selectedFile != null)
            {
                //disconnect = false;
                //isListeningToServer = false;
                string FileName = selectedFile.FileName;
                string code = ((int)MessageCodes.MC_JOIN_FILE_REQUEST).ToString();
                communicator.SendData($"{code}{FileName.Length:D5}{FileName}{communicator.UserId}");
            }

        }

        private void BtnPermissionRequests_Click(object sender, RoutedEventArgs e)
        {
            disconnect = false;
            isListeningToServer = false;
            // Open a new window for permission requests
            PermissionRequestsWindow permissionRequestsWindow = new PermissionRequestsWindow(communicator);
            permissionRequestsWindow.Show();
            Close();
        }

        private void BtnLogout_Click(object sender, RoutedEventArgs e)
        {
            string code = ((int)MessageCodes.MC_LOGOUT_REQUEST).ToString();
            communicator.SendData($"{code}");
        }

        private void remove(object sender, RoutedEventArgs e)
        {
            FileModel selectedFile = lstFiles.SelectedItem as FileModel;
            if (selectedFile != null)
            {
                // Copy the selectedFile to avoid modifying the original list
                FileModel fileToRemove = new FileModel
                {
                    FileName = selectedFile.FileName,
                    // Copy other properties as needed
                };

                // remove the .txt at the end
                int newLength = fileToRemove.FileName.Length - 4;
                string stringWithoutLast4Chars = fileToRemove.FileName.Substring(0, newLength);

                string code = ((int)MessageCodes.MC_DELETE_FILE_REQUEST).ToString();
                communicator.SendData($"{code}{stringWithoutLast4Chars.Length:D5}{stringWithoutLast4Chars}");

                // Optionally, you can keep the original list unchanged, or modify it if needed
                // lstFiles.Items.Remove(selectedFile);
            }
        }

        private void TxtNewFileName_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                if (txtNewFileName.Text.Length > 0 && IsValidMessage(txtNewFileName.Text))
                {
                    if (FileExists(txtNewFileName.Text + ".txt"))
                    {
                        lblErr.Content = "File already exists";
                        return;
                    }
                    e.Handled = true;
                    disconnect = false;
                    isListeningToServer = false;
                    string code = ((int)MessageCodes.MC_CREATE_FILE_REQUEST).ToString();
                    communicator.SendData($"{code}{txtNewFileName.Text}");

                    TextEditor textEditorWindow = new TextEditor(communicator, txtNewFileName.Text + ".txt");
                    textEditorWindow.Show();
                    Close();
                    return;
                }
            }
        }

        private bool IsValidMessage(string message)
        {
            // allow only letters, numbers, and specific special characters
            return System.Text.RegularExpressions.Regex.IsMatch(message, @"^[A-Za-z0-9,.""';:\[\]{}\-+=_!@#$%^&*()<>?/~` ]+$");
        }

        private async void Files_CloseFile(object sender, EventArgs e)
        {
            if (disconnect)
            {
                try
                {
                    string chatMessageCode = ((int)MessageCodes.MC_DISCONNECT).ToString();

                    string fullMessage = $"{chatMessageCode}{communicator.UserId:D5}";

                    communicator.SendData(fullMessage);

                    // Close the window on the UI thread
                    await Dispatcher.InvokeAsync(() => Close());
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error during closing: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private async void ReceiveServerUpdates()
        {
            try
            {
                while (isListeningToServer)
                {
                    string update = communicator.ReceiveData();
                    string code = update.Substring(0, 3); // Assuming the message code is always 3 characters

                    switch (code)
                    {
                        case "207": // MC_ADD_FILE_RESP
                            HandleAddFile(update);
                            break;
                        case "214":
                            HandleDeleteFile(update);
                            break;
                        case "200": // MC_ERR_RESP
                            HandleError(update);
                            break;
                        case "212": // MC_JOIN_FILE_RESP
                            HandleJoinFileResponse(update);
                            break;
                        case "213": // MC_LEAVE_FILE_RESP
                            HandleLeaveFileResponse(update);
                            break;
                        case "219": // mc_permission_file_req_resp
                            HandleSentPermissionRequest(update);
                            break;
                        case "401" or "403":
                            HandleLogin(update);
                            break;
                        case "300":
                            HandleDisconnect(update);
                            break;
                        case "305": // MC_APPROVE_JOIN_RESP
                            HandleJoinFile(update);
                            break;
                        case "406":
                            HandleLogout(update);
                            break;
                        case "302": // MC_APPROVE_REQ_RESP
                            break;
                        default:
                            throw new InvalidOperationException($"{code}");
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error receiving server updates: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                string msg = await Task.Run(() => communicator.ReceiveData());
            }
        }

        private void HandleSentPermissionRequest(string update)
        {
            string code = update.Substring(0, 3);
            int fileNameLen = int.Parse(update.Substring(3, 5));
            string fileName = update.Substring(8, fileNameLen);

            MessageBox.Show($"Sent request to user for file: {fileName}", "Request Sent", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void HandleJoinFile(string update)
        {
            disconnect = false;
            isListeningToServer = false;

            int fileLength = int.Parse(update.Substring(3, 5));
            string FileName = update.Substring(8, fileLength);

            Dispatcher.Invoke(() =>
            {
                TextEditor TextEditorWindow = new TextEditor(communicator, FileName);
                TextEditorWindow.Show();
                Close();
            });
        }

        private void HandleLogout(string update)
        {
            disconnect = false;
            isListeningToServer = false;

            Dispatcher.Invoke(() =>
            {
                LoginWindow loginWindow = new LoginWindow(communicator);
                loginWindow.Show();
                Close();
            });
        }

        private void HandleAddFile(string update)
        {
            string msg = update.Substring(3);

            // Create a new FileModel object and add it to the ListBox
            FileModel newFile = new FileModel { FileName = msg };

            Dispatcher.Invoke(() =>
            {
                if (lstFiles.ItemsSource is List<FileModel> fileList)
                {
                    // Find the index to insert the new file
                    int insertIndex = 0;
                    while (insertIndex < fileList.Count && string.Compare(fileList[insertIndex].FileName, newFile.FileName, StringComparison.Ordinal) < 0)
                    {
                        insertIndex++;
                    }

                    // Insert the new file at the correct position
                    fileList.Insert(insertIndex, newFile);

                    // Set the ListBox's ItemsSource again to trigger the update
                    lstFiles.ItemsSource = null;
                    lstFiles.ItemsSource = fileList;
                }
            });
        }

        private void HandleDeleteFile(string update)
        {
            string deletedFileName = update.Substring(3);

            Dispatcher.Invoke(() =>
            {
                if (lstFiles.ItemsSource is List<FileModel> fileList)
                {
                    // Find the index of the file to delete
                    int deleteIndex = fileList.FindIndex(file => file.FileName == deletedFileName);

                    // If the file is found, remove it from the list
                    if (deleteIndex != -1)
                    {
                        fileList.RemoveAt(deleteIndex);

                        // Set the ListBox's ItemsSource again to trigger the update
                        lstFiles.ItemsSource = null;
                        lstFiles.ItemsSource = fileList;
                    }
                }
            });
        }

        private void HandleError(string update)
        {
            string code = update.Substring(0, 3);
            string msg = update.Substring(3);

            if (code == "200" && msg.StartsWith("You are not allowed to join this file"))
            {
                int fileNameLen = int.Parse(msg.Substring(37, 5));
                string fileName = msg.Substring(42, fileNameLen);

                MessageBoxResult result = MessageBox.Show($"Error: You are not allowed to join this file\n\nDo you want to send a permission request to the file creator?",
                                              "Error", MessageBoxButton.YesNo, MessageBoxImage.Error);

                if (result == MessageBoxResult.Yes)
                {
                    SendPermissionRequest(fileName);
                }
            }
            else
            {
                MessageBox.Show($"Error: {msg}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void SendPermissionRequest(string fileName)
        {
            string approvalMessage = $"{(int)MessageCodes.MC_PERMISSION_FILE_REQ_REQUEST}{fileName.Length:D5}{fileName}" +
                $"{communicator.UserName.Length:D5}{communicator.UserName}";
            communicator.SendData(approvalMessage);

        }

        private bool FileExists(string fileName)
        {
            foreach (var item in lstFiles.Items)
            {
                if (item is FileModel file && file.FileName == fileName)
                {
                    return true;
                }
            }
            return false;
        }

        private void HandleJoinFileResponse(string update)
        {
            try
            {
                // Assuming the message format is "{code}{userNameLength}{userName}{fileNameLength}{FileName}"
                int lengthIndex = 3;

                // Extract user name length
                int userNameLength = int.Parse(update.Substring(lengthIndex, 5));
                lengthIndex += 5;

                // Extract user name
                string userName = update.Substring(lengthIndex, userNameLength);
                lengthIndex += userNameLength;

                // Extract file name length
                int fileNameLength = int.Parse(update.Substring(lengthIndex, 5));
                lengthIndex += 5;

                // Extract file name
                string fileName = update.Substring(lengthIndex, fileNameLength - 4);

                // Find the index of the user in the list
                int userIndex = -1;
                Dispatcher.Invoke(() => userIndex = lstUserList.Items.IndexOf($"{userName}"));

                // Update the item if found
                if (userIndex != -1)
                {
                    Dispatcher.Invoke(() => lstUserList.Items[userIndex] = $"{userName} - \"{fileName}\"");
                }
                else
                {
                    // If not found, add it to the list
                    Dispatcher.Invoke(() => lstUserList.Items.Add($"{userName} - \"{fileName}\""));
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error handling Join File response: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void HandleLeaveFileResponse(string update)
        {
            try
            {
                // Assuming the message format is "{code}{userNameLength}{userName}{fileNameLength}{FileName}"
                int lengthIndex = 3;

                // Extract user name length
                int userNameLength = int.Parse(update.Substring(lengthIndex, 5));
                lengthIndex += 5;

                // Extract user name
                string userName = update.Substring(lengthIndex, userNameLength);
                lengthIndex += userNameLength;

                // Extract file name length
                int fileNameLength = int.Parse(update.Substring(lengthIndex, 5)) + 2;
                lengthIndex += 5;

                // Extract file name
                string fileName = update.Substring(lengthIndex + 8, fileNameLength - 14);

                // Find the index of the user in the list
                int userIndex = -1;
                Dispatcher.Invoke(() => userIndex = lstUserList.Items.IndexOf($"{userName} - \"{fileName}\""));

                // Update the item if found
                if (userIndex != -1)
                {
                    Dispatcher.Invoke(() => lstUserList.Items[userIndex] = $"{userName}");
                }
                else
                {
                    // If not found, add it to the list
                    Dispatcher.Invoke(() => lstUserList.Items.Add($"{userName}"));
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error handling Leave File response: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void HandleLogin(string update)
        {
            try
            {
                // Assuming the message format is "{code}{userName}"
                int nameIndex = 3;
                // Extract user name
                string userName = update.Substring(nameIndex);

                // Find the index of the user in the list
                int userIndex = -1;
                Dispatcher.Invoke(() => lstUserList.Items.Add($"{userName}"));
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error handling Leave File response: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }

        }

        private void HandleDisconnect(string update)
        {
            try
            {
                // Assuming the message format is "{code}{userName}"
                int nameIndex = 3;

                // Extract user name
                string userName = update.Substring(nameIndex);

                // Try to remove the user with the file name first
                Dispatcher.Invoke(() => lstUserList.Items.Remove($"{userName}"));

                // If not found, try to remove the user without the file name
                if (lstUserList.Items.Contains($"{userName}"))
                {
                    Dispatcher.Invoke(() => lstUserList.Items.Remove($"{userName}"));
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error handling Disconnect: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void UpdateUserList(IEnumerable<string> userList)
        {
            // Clear the current user list
            Dispatcher.Invoke(() => lstUserList.Items.Clear());

            // Add the updated user list
            Dispatcher.Invoke(() =>
            {
                foreach (var user in userList)
                {
                    lstUserList.Items.Add(user);
                }
            });
        }
    }

    public class FileModel
    {
        public string FileName { get; set; }
    }

}

