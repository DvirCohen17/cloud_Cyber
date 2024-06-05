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
    /// Interaction logic for SignupWindow.xaml
    /// </summary>
    public partial class SignupWindow : Window
    {
        Communicator communicator;
        bool disconnect = true; // if window closed by the user disconnect

        public SignupWindow(Communicator _communicator)
        {
            InitializeComponent();
            Style = (Style)FindResource(typeof(Window));
            communicator = _communicator;
            Closing += signUp_CloseFile; // Hook up the closing event handler

        }

        private async void signUp_CloseFile(object sender, EventArgs e)
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


        private void hprlnkLogin(object sender, RoutedEventArgs e)
        {
            disconnect = false;
            LoginWindow loginWindow = new LoginWindow(communicator);
            loginWindow.Show();
            Close();
        }

        private void btnSignup_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (String.IsNullOrEmpty(txtUsername.Text) || String.IsNullOrEmpty(pwdPassword.Password) || String.IsNullOrEmpty(txtEmail.Text)
                    || communicator.ContainsSqlInjection(txtUsername.Text) || communicator.ContainsSqlInjection(pwdPassword.Password)
                    || communicator.ContainsSqlInjection(txtEmail.Text))
                {
                    lblErrMsg.Text = "Invalid username, password or email";
                    return;
                }
                string code = ((int)MessageCodes.MC_SIGNUP_REQUEST).ToString();
                string name = txtUsername.Text;
                string pass = communicator.HashPassword(pwdPassword.Password);
                string email = txtEmail.Text;

                if (!IsValidEmail(email))
                {
                    lblErrMsg.Text = "Invalid email format. Please enter a valid email address.";
                    return;
                }

                communicator.SendData($"{code}{name.Length:D5}{name}{pass.Length:D5}{pass}{email.Length:D5}{email}");

                string update = communicator.ReceiveData();
                string rep = update.Substring(0, 3);

                if (rep == ((int)MessageCodes.MC_SIGNUP_RESP).ToString())
                {
                    communicator.UserName = name;
                    communicator.UserId = int.Parse(update.Substring(3));
                    disconnect = false;
                    Files filesWindow = new Files(communicator);
                    filesWindow.Show();
                    Close();
                }
                else if (rep == ((int)MessageCodes.MC_ERROR_RESP).ToString())
                {
                    lblErrMsg.Text = update.Substring(3);
                }
            }
            catch (Exception ex)
            {
                lblErrMsg.Text = ex.Message;
            }
        }

        private bool IsValidEmail(string email)
        {
            // Use a regular expression to check the email format
            // This pattern assumes a simple email format, modify as needed
            string pattern = @"^[a-zA-Z0-9_.+-]+@gmail\.com$";
            Regex regex = new Regex(pattern);
            return regex.IsMatch(email);
        }

    }
}
