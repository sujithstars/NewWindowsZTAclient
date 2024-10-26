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
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Windows.Media.Animation;
using ZitiDesktopEdge.Models;
using ZitiDesktopEdge.ServiceClient;
using ZitiDesktopEdge.DataStructures;

using NLog;
using QRCoder;
using System.Text.RegularExpressions;
using System.Web.UI.WebControls;
using System.Net.Http;
using static ZitiDesktopEdge.MFAScreen;
using static System.Windows.Forms.AxHost;

namespace ZitiDesktopEdge {
	/// <summary>
	/// Interaction logic for MFA.xaml
	/// </summary>
	public partial class ActivationScreen : UserControl {
		private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        public delegate void CloseAction(bool isComplete);
        public event CloseAction OnClose;

        private MainWindow mainWindow;

        public ActivationScreen()
        {
            InitializeComponent();
        }

        async private void DoActivation()
		{
            var httpClient = new HttpClient();

            // Create a dictionary of the form data
            var formData = new Dictionary<string, string>
            {
                { "action", "setting_app" },
                { "customerKey", customerKey.Text },
                { "friendlyName", friendlyName.Text }
            };

            // Encode the data as form-urlencoded
            var content = new FormUrlEncodedContent(formData);

            try
            {
                // Post the data to the server
                var response = await httpClient.PostAsync("http://127.0.0.1:8001", content);
                if (response.IsSuccessStatusCode)
                {
                    var responseContent = await response.Content.ReadAsStringAsync();
                    if (responseContent.Contains("{\"registration\":\"success\"}"))
                    {
                        if (this.mainWindow.isToastEnabled())
                        {
                            this.mainWindow.ShowToast("Shield Activated");
                        }
                        this.OnClose?.Invoke(false);
                    }
                    else
                    {
                        if (this.mainWindow.isToastEnabled())
                        {
                            this.mainWindow.ShowToast("Activated failed.");
                        }
                    }
                }
                else
                {
                    this.mainWindow.ShowToast("Activated failed. Unable to connect.");
                }
            }
            catch (Exception ex)
            {
                this.mainWindow.ShowToast("Activated failed. Unable to connect.");
            }
        }
        private void ExecuteClose(object sender, MouseButtonEventArgs e)
        {
            this.OnClose?.Invoke(false);
        }

        internal void showActivation(MainWindow mainWindow)
        {
            this.mainWindow = mainWindow;
        }
    }
}
