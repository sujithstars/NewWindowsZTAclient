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

using System.Net;
using System.Windows.Media.Animation;
using ZitiDesktopEdge.Models;
using ZitiDesktopEdge.ServiceClient;
using ZitiDesktopEdge.DataStructures;
using System.IO;
using NLog;
using QRCoder;
using System.Text.RegularExpressions;
using System.Web.UI.WebControls;
using System.Net.Http;
using static ZitiDesktopEdge.MFAScreen;
using static System.Windows.Forms.AxHost;
using System.Collections;
using System.Text.Json;
using System.Reflection;

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

        async public void DoActivation()
        {
            string exePath = Assembly.GetExecutingAssembly().Location;
            string rootFolderPath = System.IO.Path.GetDirectoryName(exePath);
            string filePath = System.IO.Path.Combine(rootFolderPath, "File.json");

            var httpClient = new HttpClient();
            Dictionary<string, string> formData = null;
            if (File.Exists(filePath))
            {
                formData = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(filePath));
            }
            else
            {
                formData = new Dictionary<string, string>
     {
         { "action", "setting_app" },
         { "customerKey", customerKey.Text },
         { "friendlyName", friendlyName.Text }
     };
            }
            //fffeeeyyygggrre333
            
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
                                string jsonString = JsonSerializer.Serialize(formData);


                                try
                                {
                                    // Write the JSON string to the file
                                    File.WriteAllText(filePath, jsonString);
                                    Console.WriteLine("JSON data has been saved to " + filePath);
                                }
                                catch (Exception ex)
                                {
                                    Console.WriteLine("An error occurred: " + ex.Message);
                                }
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
                        this.OnClose?.Invoke(false);
                    }
                }
                catch (Exception ex)
                {
                    this.mainWindow.ShowToast("Activated failed. Unable to connect.");
                    this.OnClose?.Invoke(false);

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
