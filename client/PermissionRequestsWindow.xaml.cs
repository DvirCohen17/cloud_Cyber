using System.Collections.ObjectModel;
using System.Windows.Input;
using System.Windows;
using System;

namespace client_side
{
    public partial class PermissionRequestsWindow : Window
    {
        public ObservableCollection<PermissionRequest> PermissionRequests { get; set; }
        Communicator communicator;
        public PermissionRequestsWindow(Communicator communicator)
        {
            InitializeComponent();
            Style = (Style)FindResource(typeof(Window));
            this.communicator = communicator;

            getRequests(true);
        }

        private void BtnExit_Click(object sender, RoutedEventArgs e)
        {
            Files mainWindow = new Files(communicator);
            mainWindow.Show();
            Close();
        }

        private void BtnRefresh_Click(object sender, RoutedEventArgs e)
        {
            // Check if PermissionRequests is not null before clearing
            if (PermissionRequests != null)
            {
                PermissionRequests.Clear();
                getRequests(false);
            }
            else
            {
                // If PermissionRequests is null, initialize it and then get requests
                PermissionRequests = new ObservableCollection<PermissionRequest>();
                DataContext = this;
                getRequests(false);
            }
        }
            
        private void getRequests(bool first)
        {
            try
            {
                BtnRefresh.IsEnabled = false;

                //ShowLoadingIndicator();

                // Check if PermissionRequests is not null before clearing
                if (PermissionRequests != null)
                {
                    PermissionRequests.Clear();
                    DataContext = this;
                }
                else
                {
                    // If PermissionRequests is null, initialize it
                    PermissionRequests = new ObservableCollection<PermissionRequest>();
                    DataContext = this;
                }

                string code = ((int)MessageCodes.MC_GET_USERS_PERMISSIONS_REQ_REQUEST).ToString();
                communicator.SendData($"{code}");

                string update;
                if (!first)
                {
                    update = communicator.ReceiveData();
                }
                update = communicator.ReceiveData();
                string repCode = update.Substring(0, 3);

                if (repCode == ((int)MessageCodes.MC_GET_USERS_PERMISSIONS_REQ_RESP).ToString() &&
                    update.Length > 3)
                {
                    // Assuming the message format is "{code}{request1}{request2}..."
                    int lengthIndex = 3;

                    // Extract and add each permission request to the collection
                    while (lengthIndex < update.Length)
                    {
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
                        string fileName = update.Substring(lengthIndex, fileNameLength);
                        lengthIndex += fileNameLength;

                        // Check if PermissionRequests is not null before adding new items
                        if (PermissionRequests != null)
                        {
                            // Add the PermissionRequest to the collection
                            Dispatcher.Invoke(() => PermissionRequests.Add(new PermissionRequest { UserName = userName, FileName = fileName }));
                        }
                    }
                }
                BtnRefresh.IsEnabled = true;
                //HideLoadingIndicator();

            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        /*
        private void ShowLoadingIndicator()
        {
            loadingSpinner.Visibility = Visibility.Visible;
        }

        private void HideLoadingIndicator()
        {
            loadingSpinner.Visibility = Visibility.Collapsed;
        }
        */
        // Command handlers for approval and rejection
        private void ApproveButtonClick(object sender, RoutedEventArgs e)
        {
            if (sender is FrameworkElement element && element.DataContext is PermissionRequest permissionRequest)
            {
                HandlePermissionAction(permissionRequest, MessageCodes.MC_APPROVE_PERMISSION_REQUEST);
            }
        }

        private void RejectButtonClick(object sender, RoutedEventArgs e)
        {
            if (sender is FrameworkElement element && element.DataContext is PermissionRequest permissionRequest)
            {
                HandlePermissionAction(permissionRequest, MessageCodes.MC_REJECT_PERMISSION_REQUEST);
            }
        }

        private void HandlePermissionAction(PermissionRequest permissionRequest, MessageCodes actionCode)
        {
            try
            {
                string actionMessage = $"{(int)actionCode}{permissionRequest.FileName.Length:D5}{permissionRequest.FileName}{permissionRequest.UserName.Length:D5}{permissionRequest.UserName}";
                communicator.SendData(actionMessage);

                string update = communicator.ReceiveData();
                string repCode = update.Substring(0, 3);

                if (repCode == ((int)MessageCodes.MC_REJECT_PERMISSION_RESP).ToString() || repCode == ((int)MessageCodes.MC_APPROVE_PERMISSION_RESP).ToString())
                {
                    PermissionRequests.Remove(permissionRequest);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        public class PermissionRequest
        {
            public string UserName { get; set; }
            public string FileName { get; set; }
            // Add more properties as needed
        }
    }
}
