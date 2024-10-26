using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ZitiDesktopEdge;

namespace Ziti.Desktop.Edge.Utils
{
    internal class ProxyWatchdog
    {
        private static ProxyWatchdog shared;
        public static ProxyWatchdog Shared { 
            set { shared = value; }
            get { return shared; } 
        }

        private CancellationTokenSource cancellationToken;

        private bool isRegistered = false;
        public bool IsRegistered { get { return isRegistered; } }

        private bool isActive = false;
        public bool IsActive { get { return isActive; } }

        private bool isRunning = false;
        public bool IsRunning { get { return isRunning; } }


        private int failedPings = 0;


        public void Start()
        {
            this.cancellationToken = new CancellationTokenSource();
            StartLoop(cancellationToken.Token);
        }

        private async void StartLoop(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                await CheckRegistrationStatusAsync();
                try
                {
                    await Task.Delay(30000, cancellationToken); // Wait for 30 seconds or until cancellation
                }
                catch (TaskCanceledException)
                {
                    // Handle the task cancellation here if needed
                    break;
                }
            }
        }

        public async Task CheckRegistrationStatusAsync()
        {
            var httpClient = new HttpClient();
            try
            {
                // Send a GET request to the specified Uri.
                var response = await httpClient.GetAsync("http://127.0.0.1:8001/registrationstatus");

                // Ensure the request was successful.
                response.EnsureSuccessStatusCode();

                // Read the response content as a string.
                var content = await response.Content.ReadAsStringAsync();

                // Parse the JSON response.
                //var result = JsonSerializer.Deserialize<RegistrationStatus>(content);
                var result = JsonConvert.DeserializeObject<RegistrationStatus>(content);


                // Check the registration status.
                if (result != null && result.Registered.ToLower() == "true")
                {
                    this.isRegistered = true;
                    this.isRunning = true;
                    this.failedPings = 0;
                }
                else if (result != null)
                {
                    this.isRegistered = false;
                    this.isRunning = true;
                    this.failedPings = 0;
                }
            }
            catch (HttpRequestException e)
            {
                Console.WriteLine($"Request exception: {e.Message}");
                failedPings++;
                this.isRegistered = false;
                this.isRunning = false;
                if (failedPings > 2)
                {
                    StartProxy();
                    this.failedPings = 0;
                }
            }
            catch (JsonException e)
            {
                Console.WriteLine($"JSON parsing exception: {e.Message}");
                this.isRegistered = false;
                this.isRunning = false;
                this.failedPings = 0;
            }
        }


        public void Stop()
        {
            this.cancellationToken.Cancel(); 
        }

        // Duplicates the code that is in MainWindow. Will probably merge them later, but
        // for now this will do. 
        private static void StartProxy()
        {
            Console.WriteLine("Restarting proxy");
            Process process = new Process();

            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = "cscript.exe", 
                Arguments = "ShieldProxy.vbs", 
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            process.StartInfo = startInfo;
            process.Start();

            process.WaitForExit();
            process.Close();
        }
    }
}
