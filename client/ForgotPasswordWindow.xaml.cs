using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;


namespace client_side
{
    /// <summary>
    /// Interaction logic for ForgotPasswordWindow.xaml
    /// </summary>
    public partial class ForgotPasswordWindow : Window
    {
        private Communicator communicator;
        bool disconnect = true; // if window closed by the user disconnect

        public ForgotPasswordWindow(Communicator _communicator)
        {
            communicator = _communicator;
            InitializeComponent();
            Style = (Style)FindResource(typeof(Window));

            Closing += forgotPass_CloseFile; // Hook up the closing event handler
        }

        private async void forgotPass_CloseFile(object sender, EventArgs e)
        {
            if (disconnect)
            {
                try
                {
                    string chatMessageCode = ((int)MessageCodes.MC_DISCONNECT).ToString();

                    string fullMessage = $"{chatMessageCode}";

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

        private async void btnConfirm_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // Validate input fields
                if (string.IsNullOrEmpty(txtUserName.Text) ||
                    string.IsNullOrEmpty(txtOldPassword.Password) ||
                    string.IsNullOrEmpty(txtNewPassword.Password))
                {
                    lblErrMsg.Content = "Please fill in all fields.";
                    return;
                }

                string userName = txtUserName.Text;
                string oldPassword = communicator.HashPassword(txtOldPassword.Password);
                string newPassword = communicator.HashPassword(txtNewPassword.Password);

                string code = ((int)MessageCodes.MC_FORGOT_PASSW_REQUEST).ToString();

                communicator.SendData($"{code}{userName.Length:D5}{userName}{oldPassword.Length:D5}{oldPassword}{newPassword.Length:D5}{newPassword}");

                // Receive response from the server
                string update = communicator.ReceiveData();
                string rep = update.Substring(0, 3);

                // Check the response from the server
                if (update.StartsWith(((int)MessageCodes.MC_FORGOT_PASSW_RESP).ToString()))
                {
                    string lengthString = update.Substring(3, 5);
                    int Namelength = int.Parse(lengthString);
                    string Name = update.Substring(8, Namelength);

                    string Id = update.Substring(8 + Namelength);
                    communicator.UserName = Name;
                    communicator.UserId = int.Parse(Id);
                    disconnect = false;
                    Files filesWindow = new Files(communicator);
                    filesWindow.Show();
                    Close();
                }
                else
                {
                    // Handle other responses or errors from the server
                    lblErrMsg.Content = update.Substring(3);
                }
            }
            catch (Exception ex)
            {
                lblErrMsg.Content = ex.Message;
            }
        }


        private void btnReturn_Click(object sender, RoutedEventArgs e)
        {
            disconnect = false;
            LoginWindow loginWindow = new LoginWindow(communicator);
            loginWindow.Show();
            Close();
        }
    }
}
