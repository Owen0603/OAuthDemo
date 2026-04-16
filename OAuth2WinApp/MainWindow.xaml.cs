using System.Windows;

namespace OAuth2WinApp
{
    public partial class MainWindow : Window
    {
        private readonly AuthManager _authManager = new();

        public MainWindow()
        {
            InitializeComponent();
            _authManager.PropertyChanged += AuthManager_PropertyChanged;
        }

        private void AuthManager_PropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
        {
            Dispatcher.Invoke(() => UpdateUI());
        }

        private void UpdateUI()
        {
            if (_authManager.IsLoggedIn)
            {
                TitleText.Text = "登录成功!";
                LoginPanel.Visibility = Visibility.Collapsed;
                LoggedInPanel.Visibility = Visibility.Visible;
                UsernameText.Text = _authManager.Username;
                EmailText.Text = _authManager.Email;
                TokenText.Text = _authManager.AccessToken.Length > 20
                    ? _authManager.AccessToken[..20] + "..."
                    : _authManager.AccessToken;
            }
            else
            {
                TitleText.Text = "OAuth 2.0 登录 Demo";
                LoginPanel.Visibility = Visibility.Visible;
                LoggedInPanel.Visibility = Visibility.Collapsed;
            }

            LoginButton.Visibility = _authManager.IsLoading ? Visibility.Collapsed : Visibility.Visible;
            LoadingText.Visibility = _authManager.IsLoading ? Visibility.Visible : Visibility.Collapsed;

            if (!string.IsNullOrEmpty(_authManager.ErrorMessage))
            {
                ErrorText.Text = _authManager.ErrorMessage;
                ErrorText.Visibility = Visibility.Visible;
            }
            else
            {
                ErrorText.Visibility = Visibility.Collapsed;
            }
        }

        private async void LoginButton_Click(object sender, RoutedEventArgs e)
        {
            await _authManager.StartOAuthLoginAsync();
        }

        private void LogoutButton_Click(object sender, RoutedEventArgs e)
        {
            _authManager.Logout();
        }
    }
}
