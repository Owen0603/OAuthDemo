using System.Windows;
using System.Windows.Threading;

namespace OAuth2WinApp
{
    public partial class App : Application
    {
        public App()
        {
            DispatcherUnhandledException += (_, e) =>
            {
                MessageBox.Show(
                    $"Error:\n{e.Exception.Message}\n\n{e.Exception.StackTrace}",
                    "OAuth2WinApp - Unhandled Exception",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
                e.Handled = true;
            };
        }
    }
}
