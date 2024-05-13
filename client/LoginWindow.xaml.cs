using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
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
    /// Interaction logic for LoginWindow.xaml
    /// </summary>
    public partial class LoginWindow : Window
    {
        private Communicator communicator;
        bool disconnect = true; // if window closed by the user disconnect

        public LoginWindow()
        {
            InitializeComponent();
            Style = (Style)FindResource(typeof(Window));

            StreamReader sr = new StreamReader(".\\config.txt");
            string? line = sr.ReadLine();
            sr.Close();
            if (line == null)
            {
                throw new Exception("Please create file `config.txt` in the directory with the binary and set its contents in the  following format: `SERVER_IP,SERVER_PORT`");
            }
            string[] ip_port = line.Split(",");
            try
            {
                communicator = new Communicator(ip_port[0], int.Parse(ip_port[1]));
                Closing += login_CloseFile; // Hook up the closing event handler

            }
            catch (Exception)
            {
                MessageBox.Show("An error occured while connecting to the server.");
                Application.Current.Shutdown();
                Environment.Exit(0);
            }

        }

        private async void login_CloseFile(object sender, EventArgs e)
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

        public LoginWindow(Communicator _communicator)
        {
            InitializeComponent();
            Style = (Style)FindResource(typeof(Window));
            communicator = _communicator;
            Closing += login_CloseFile; // Hook up the closing event handler
        }

        private void btnLogin_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (String.IsNullOrEmpty(txtUsername.Text) || String.IsNullOrEmpty(pwdPassword.Password)
                    || communicator.ContainsSqlInjection(txtUsername.Text) || communicator.ContainsSqlInjection(pwdPassword.Password))
                {
                    lblErrMsg.Text = "Invalid username or password";
                    return;
                }

                string code = ((int)MessageCodes.MC_LOGIN_REQUEST).ToString();
                string name = txtUsername.Text;
                string pass = communicator.HashPassword(pwdPassword.Password);
                communicator.SendData($"{code}{name.Length:D5}{name}{pass.Length:D5}{pass}");

                string update = communicator.ReceiveData();
                string rep = update.Substring(0, 3);

                if (rep == ((int)MessageCodes.MC_LOGIN_RESP).ToString())
                {
                    string lengthString = update.Substring(3 , 5);
                    int Namelength = int.Parse(lengthString);
                    string userName = update.Substring(8, Namelength);

                    string Id = update.Substring(8 + Namelength);
                    communicator.UserName = userName;
                    communicator.UserId = int.Parse(Id);
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
            catch(Exception ex)
            {
                lblErrMsg.Text = ex.Message;
            }
        }

        private void hprlnkSignup(object sender, RoutedEventArgs e)
        {
            disconnect = false;
            SignupWindow signupWindow = new SignupWindow(communicator);
            signupWindow.Show();
            Close();
        }

        private void hprlnkForgotPassword(object sender, RoutedEventArgs e)
        {
            disconnect = false;
            ForgotPasswordWindow forgotPassWindow = new ForgotPasswordWindow(communicator);
            forgotPassWindow.Show();
            Close();
        }

    }
}
