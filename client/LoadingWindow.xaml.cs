using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace client_side
{
    public partial class LoadingWindow : Window
    {
        private System.Windows.Threading.DispatcherTimer timer;

        public LoadingWindow()
        {
            InitializeComponent();

            // Initialize the timer
            timer = new System.Windows.Threading.DispatcherTimer();
            timer.Interval = TimeSpan.FromSeconds(10);
            timer.Tick += Timer_Tick;
            timer.Start();

            // Start the loading animation
            StartLoadingAnimation();
        }

        private void StartLoadingAnimation()
        {
            // Get the loading animation storyboard
            Storyboard loadingAnimation = (Storyboard)FindResource("LoadingAnimation");
            // Begin the animation
            loadingAnimation.Begin();
        }

        private void Timer_Tick(object sender, EventArgs e)
        {
            // Close the loading screen and open the main window
            LoginWindow mainWindow = new LoginWindow();
            mainWindow.Show();
            Close();

            // Stop the timer after opening the main window
            timer.Stop();
        }

    }
}