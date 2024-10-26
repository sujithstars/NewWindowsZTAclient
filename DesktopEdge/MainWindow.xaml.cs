using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Input;
using System.IO;
using System.ServiceProcess;
using System.Linq;
using System.Diagnostics;
using System.Windows.Controls;
using System.Drawing;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Media.Animation;
using System.Web;
using Microsoft.Toolkit.Uwp.Notifications;

using ZitiDesktopEdge.Models;
using ZitiDesktopEdge.DataStructures;
using ZitiDesktopEdge.ServiceClient;
using ZitiDesktopEdge.Utility;

using NLog;
using NLog.Config;
using NLog.Targets;
using Microsoft.Win32;

using System.Windows.Interop;
using Windows.UI.Notifications;
using Windows.Data.Xml.Dom;
using Ziti.Desktop.Edge.Models;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System.Security.Claims;
using System.Text;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Windows.Forms.VisualStyles;
using Ziti.Desktop.Edge;
using System.Net.Http;
using System.Net.Http.Headers;
using NLog.Fluent;
using forms = System.Windows.Forms;
using System.Reflection;
using Lada.Maths;
using System.Text.RegularExpressions;
using System.Net.Sockets;
using System.Security.Principal;
using Ziti.Desktop.Edge.Utils;

namespace ZitiDesktopEdge {

	public partial class MainWindow : Window {
		private static readonly Logger logger = LogManager.GetCurrentClassLogger();
		
		public string RECOVER = "RECOVER";
		public System.Windows.Forms.NotifyIcon notifyIcon;
		public string Position = "Bottom";
		private DateTime _startDate;
		private System.Windows.Forms.Timer _tunnelUptimeTimer;
		private DataClient serviceClient = null;
		MonitorClient monitorClient = null;
		private bool _isAttached = true;
		private bool _isServiceInError = false;
		private int _right = 75;
		private int _left = 75;
		private int _top = 30;
		public bool IsUpdateAvailable = false;
		public int NotificationsShownCount = 0;
		private double _maxHeight = 800d;
		public string CurrentIcon = "white";
		private string[] suffixes = { "Bps", "kBps", "mBps", "gBps", "tBps", "pBps" };
		private string _blurbUrl = "";
        const string testingEndpoint = "https://j8w70hi9q1.execute-api.us-east-1.amazonaws.com/beta/";
		const string testingAPIKey = "EŖȞ͐юզـݑࠕ५ਬତపൟ๿ཨၜᅦቚ፣ᑮᔫᘦ᝼᡽᤼ᩜ᭎᰹ᴺḾὓⁿ⅟≜⍨⑭╄♻❤";

        private CancellationTokenSource cancellationActivationToken;

        private static SemaphoreSlim semaphoreSlim = new SemaphoreSlim(1, 1);

		static System.Reflection.Assembly asm = System.Reflection.Assembly.GetExecutingAssembly();

		public static string ThisAssemblyName;
		public static string ExecutionDirectory;
		public static string ExpectedLogPathRoot;
		public static string ExpectedLogPathUI;
		public static string ExpectedLogPathServices;

		private static ZDEWViewState state;
		static MainWindow() {
			asm = System.Reflection.Assembly.GetExecutingAssembly();
			ThisAssemblyName = asm.GetName().Name;
			state = (ZDEWViewState)Application.Current.Properties["ZDEWViewState"];
#if DEBUG
			//ExecutionDirectory = @"C:\Program Files (x86)\Intrusion\Intrusion Desktop Shield";
			ExecutionDirectory = @"C:\Program Files (x86)";
#else
            ExecutionDirectory = Path.GetDirectoryName(asm.Location);
#endif
            ExpectedLogPathRoot = Path.Combine(ExecutionDirectory, "logs");
			ExpectedLogPathUI = Path.Combine(ExpectedLogPathRoot, "UI", $"{ThisAssemblyName}.log");
			ExpectedLogPathServices = Path.Combine(ExpectedLogPathRoot, "service", $"ziti-tunneler.log");

			Console.WriteLine("Launching DNS Proxy");
			RunProxy();
        }

		private static void RunProxy()
		{
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

			string output = process.StandardOutput.ReadToEnd();

			process.WaitForExit();
			process.Close();
		}

		async private void IdentityMenu_OnMessage(string message) {
			await ShowBlurbAsync(message, "");
		}

		private void SystemEvents_DisplaySettingsChanged(object sender, EventArgs e) {
			LoadIdentities(true);
		}

		private List<ZitiIdentity> identities {
			get {
				return (List<ZitiIdentity>)Application.Current.Properties["Identities"];
			}
		}

		/// <summary>
		/// The MFA Toggle was toggled
		/// </summary>
		/// <param name="isOn">True if the toggle was on</param>
		private async void MFAToggled(bool isOn) {
			if (isOn) {
				ShowLoad("Generating MFA", "MFA Setup Commencing, please wait");

				await serviceClient.EnableMFA(this.IdentityMenu.Identity.Identifier);
			} else {
				this.ShowMFA(IdentityMenu.Identity, 3);
			}

			HideLoad();
		}

		/// <summary>
		/// When a Service Client is ready to setup the MFA Authorization
		/// </summary>
		/// <param name="sender">The service client</param>
		/// <param name="e">The MFA Event</param>
		private void ServiceClient_OnMfaEvent(object sender, MfaEvent mfa) {
			HideLoad();
			this.Dispatcher.Invoke(async () => {
				if (mfa.Action == "enrollment_challenge") {
					string url = HttpUtility.UrlDecode(mfa.ProvisioningUrl);
					string secret = HttpUtility.ParseQueryString(url)["secret"];
					this.IdentityMenu.Identity.RecoveryCodes = mfa?.RecoveryCodes?.ToArray();
					SetupMFA(this.IdentityMenu.Identity, url, secret);
				} else if (mfa.Action == "auth_challenge") {
					for (int i = 0; i < identities.Count; i++) {
						if (identities[i].Identifier == mfa.Identifier) {
							identities[i].WasNotified = false;
							identities[i].WasFullNotified = false;
							identities[i].IsMFAEnabled = true;
							identities[i].IsAuthenticated = false;
							identities[i].IsTimingOut = false;
							break;
						}
					}
				} else if (mfa.Action == "enrollment_verification") {
					if (mfa.Successful) {
						var found = identities.Find(id => id.Identifier == mfa.Identifier);
						for (int i = 0; i < identities.Count; i++) {
							if (identities[i].Identifier == mfa.Identifier) {
								identities[i].WasNotified = false;
								identities[i].WasFullNotified = false;
								identities[i].IsMFAEnabled = mfa.Successful;
								identities[i].IsAuthenticated = mfa.Successful;
								identities[i].IsTimingOut = false;
								identities[i].LastUpdatedTime = DateTime.Now;
								for (int j = 0; j < identities[i].Services.Count; j++) {
									identities[i].Services[j].TimeUpdated = DateTime.Now;
									identities[i].Services[j].TimeoutRemaining = identities[i].Services[j].Timeout;
								}
								found = identities[i];
								break;
							}
						}
						if (this.IdentityMenu.Identity != null && this.IdentityMenu.Identity.Identifier == mfa.Identifier) this.IdentityMenu.Identity = found;
						ShowMFARecoveryCodes(found);
					} else {
						await ShowBlurbAsync("Provided code could not be verified", "");
					}
				} else if (mfa.Action == "enrollment_remove") {
					if (mfa.Successful) {
						var found = identities.Find(id => id.Identifier == mfa.Identifier);
						for (int i = 0; i < identities.Count; i++) {
							if (identities[i].Identifier == mfa.Identifier) {
								identities[i].WasNotified = false;
								identities[i].WasFullNotified = false;
								identities[i].IsMFAEnabled = false;
								identities[i].IsAuthenticated = false;
								identities[i].LastUpdatedTime = DateTime.Now;
								identities[i].IsTimingOut = false;
								for (int j = 0; j < identities[i].Services.Count; j++) {
									identities[i].Services[j].TimeUpdated = DateTime.Now;
									identities[i].Services[j].TimeoutRemaining = 0;
								}
								found = identities[i];
								break;
							}
						}
						if (this.IdentityMenu.Identity != null && this.IdentityMenu.Identity.Identifier == mfa.Identifier) this.IdentityMenu.Identity = found;
						await ShowBlurbAsync("MFA Disabled, Service Access Can Be Limited", "");
					} else {
						await ShowBlurbAsync("MFA Removal Failed", "");
					}
				} else if (mfa.Action == "mfa_auth_status") {
					var found = identities.Find(id => id.Identifier == mfa.Identifier);
					for (int i=0; i<identities.Count; i++) {
						if (identities[i].Identifier == mfa.Identifier) {
							identities[i].WasNotified = false;
							identities[i].WasFullNotified = false;
							identities[i].IsTimingOut = false;
							identities[i].IsAuthenticated = mfa.Successful;
							identities[i].LastUpdatedTime = DateTime.Now;
							for (int j=0; j<identities[i].Services.Count; j++) {
								identities[i].Services[j].TimeUpdated = DateTime.Now;
								identities[i].Services[j].TimeoutRemaining = identities[i].Services[j].Timeout;
							}
							found = identities[i];
							break;
						}
					}
					if (this.IdentityMenu.Identity != null && this.IdentityMenu.Identity.Identifier == mfa.Identifier) this.IdentityMenu.Identity = found;
					// serviceClient.GetStatusAsync();
					// ShowBlurb("mfa authenticated: " + mfa.Successful, "");
				} else {
					await ShowBlurbAsync ("Unexpected error when processing MFA", "");
					logger.Error("unexpected action: " + mfa.Action);
				}
				LoadIdentities(true);
			});
		}

		/// <summary>
		/// Show the MFA Setup Modal
		/// </summary>
		/// <param name="identity">The Ziti Identity to Setup</param>
		public void SetupMFA(ZitiIdentity identity, string url, string secret) {
			MFASetup.Opacity = 0;
			MFASetup.Visibility = Visibility.Visible;
			MFASetup.Margin = new Thickness(0, 0, 0, 0);
			MFASetup.BeginAnimation(Grid.OpacityProperty, new DoubleAnimation(1, TimeSpan.FromSeconds(.3)));
			MFASetup.BeginAnimation(Grid.MarginProperty, new ThicknessAnimation(new Thickness(30, 30, 30, 30), TimeSpan.FromSeconds(.3)));
			MFASetup.ShowSetup(identity, url, secret);
			ShowModal();
		}

		/// <summary>
		/// Show the MFA Authentication Screen when it is time to authenticate
		/// </summary>
		/// <param name="identity">The Ziti Identity to Authenticate</param>
		public void MFAAuthenticate(ZitiIdentity identity) {
			this.ShowMFA(identity, 1);
		}

		/// <summary>
		/// Show MFA for the identity and set the type of screen to show
		/// </summary>
		/// <param name="identity">The Identity that is currently active</param>
		/// <param name="type">The type of screen to show - 1 Setup, 2 Authenticate, 3 Remove MFA, 4 Regenerate Codes</param>
		private void ShowMFA(ZitiIdentity identity, int type) {
			MFASetup.Opacity = 0;
			MFASetup.Visibility = Visibility.Visible;
			MFASetup.Margin = new Thickness(0, 0, 0, 0);

			DoubleAnimation animatin = new DoubleAnimation(1, TimeSpan.FromSeconds(.3));
			animatin.Completed += Animatin_Completed;
			MFASetup.BeginAnimation(Grid.OpacityProperty, animatin);
			MFASetup.BeginAnimation(Grid.MarginProperty, new ThicknessAnimation(new Thickness(30, 30, 30, 30), TimeSpan.FromSeconds(.3)));

			MFASetup.ShowMFA(identity, type);

			ShowModal();
		}

		private void Animatin_Completed(object sender, EventArgs e) {
			MFASetup.AuthCode.Focusable = true;
			MFASetup.AuthCode.Focus();
		}

		/// <summary>
		/// Show the MFA Recovery Codes
		/// </summary>
		/// <param name="identity">The Ziti Identity to Authenticate</param>
		async public void ShowMFARecoveryCodes(ZitiIdentity identity) {
			if (identity.IsMFAEnabled) {
				if (identity.IsAuthenticated&& identity.RecoveryCodes!=null) {
					MFASetup.Opacity = 0;
					MFASetup.Visibility = Visibility.Visible;
					MFASetup.Margin = new Thickness(0, 0, 0, 0);
					MFASetup.BeginAnimation(Grid.OpacityProperty, new DoubleAnimation(1, TimeSpan.FromSeconds(.3)));
					MFASetup.BeginAnimation(Grid.MarginProperty, new ThicknessAnimation(new Thickness(30, 30, 30, 30), TimeSpan.FromSeconds(.3)));

					MFASetup.ShowRecovery(identity.RecoveryCodes, identity);

					ShowModal();
				} else {
					this.ShowMFA(IdentityMenu.Identity, 2);
				}
			} else {
				await ShowBlurbAsync("MFA is not setup on this Identity", "");
			}
		}

		/// <summary>
		/// Show the modal, aniimating opacity
		/// </summary>
		private void ShowModal() {
			ModalBg.Visibility = Visibility.Visible;
			ModalBg.Opacity = 0;
			DoubleAnimation animation = new DoubleAnimation(.8, TimeSpan.FromSeconds(.3));
			ModalBg.BeginAnimation(Grid.OpacityProperty, animation);
		}

		/// <summary>
		/// Close the various MFA windows
		/// </summary>
		/// <param name="sender">The close button</param>
		/// <param name="e">The event arguments</param>
		private void CloseComplete(object sender, EventArgs e) {
			MFASetup.Visibility = Visibility.Collapsed;
            ActivationScreen.Visibility = Visibility.Collapsed;
        }

		/// <summary>
		/// Hide the modal animating the opacity
		/// </summary>
		private void HideModal() {
			DoubleAnimation animation = new DoubleAnimation(0, TimeSpan.FromSeconds(.3));
			animation.Completed += ModalHideComplete;
			ModalBg.BeginAnimation(Grid.OpacityProperty, animation);
		}

		/// <summary>
		/// When the animation completes, set the visibility to avoid UI object conflicts
		/// </summary>
		/// <param name="sender">The animation</param>
		/// <param name="e">The event</param>
		private void ModalHideComplete(object sender, EventArgs e) {
			ModalBg.Visibility = Visibility.Collapsed;
		}

		/// <summary>
		/// Close the MFA Screen with animation
		/// </summary>
		private void DoClose(bool isComplete) {
			DoubleAnimation animation = new DoubleAnimation(0, TimeSpan.FromSeconds(.3));
			ThicknessAnimation animateThick = new ThicknessAnimation(new Thickness(0, 0, 0, 0), TimeSpan.FromSeconds(.3));
			animation.Completed += CloseComplete;
			MFASetup.BeginAnimation(Grid.OpacityProperty, animation);
			MFASetup.BeginAnimation(Grid.MarginProperty, animateThick);
			HideModal();
			if (isComplete) {
				if (MFASetup.Type == 1) {
					for (int i=0; i<identities.Count; i++) {
						if (identities[i].Identifier == MFASetup.Identity.Identifier) {
							identities[i] = MFASetup.Identity;
							identities[i].LastUpdatedTime = DateTime.Now;
						}
					}
				}
			}
			if (IdentityMenu.IsVisible) {
				if (isComplete) {
					if (MFASetup.Type == 2) {
						ShowRecovery(IdentityMenu.Identity);
					} else if (MFASetup.Type == 3) {
					} else if (MFASetup.Type == 4) {
						ShowRecovery(IdentityMenu.Identity);
					}
				}
				IdentityMenu.UpdateView();
			}
			LoadIdentities(true);
		}

        private void AddIdentity(ZitiIdentity id) {
			semaphoreSlim.Wait();
			if (!identities.Any(i => id.Identifier == i.Identifier)) {
				identities.Add(id);
			}
			semaphoreSlim.Release();
		}

        private void DashboardButton_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
			if ((String)(button.Content) == "Shield Dashboard")
			{
				System.Diagnostics.Process.Start("http://127.0.0.1:8001/");
			}
			else if ((String)(button.Content) == "Shield Unavailable")
            {
				ActivationScreen.Opacity = 0;
				ActivationScreen.Visibility = Visibility.Visible;
				ActivationScreen.Margin = new Thickness(0, 0, 0, 0);
				ActivationScreen.BeginAnimation(Grid.OpacityProperty, new DoubleAnimation(1, TimeSpan.FromSeconds(.3)));
				ActivationScreen.BeginAnimation(Grid.MarginProperty, new ThicknessAnimation(new Thickness(30, 30, 30, 30), TimeSpan.FromSeconds(.3)));
				ActivationScreen.ActivationBrush.Visibility = Visibility.Visible;
				ActivationScreen.ActivationArea.Visibility = Visibility.Visible;
				ActivationScreen.customerKey.Focus();
				ActivationScreen.Close.Visibility = Visibility.Visible;
				ActivationScreen.showActivation(this);
				ShowModal();
			}
            else if ((String)(button.Content) == "Activate")
            {
                ActivationScreen.Opacity = 0;
                ActivationScreen.Visibility = Visibility.Visible;
                ActivationScreen.Margin = new Thickness(0, 0, 0, 0);
                ActivationScreen.BeginAnimation(Grid.OpacityProperty, new DoubleAnimation(1, TimeSpan.FromSeconds(.3)));
                ActivationScreen.BeginAnimation(Grid.MarginProperty, new ThicknessAnimation(new Thickness(30, 30, 30, 30), TimeSpan.FromSeconds(.3)));
                ActivationScreen.ActivationBrush.Visibility = Visibility.Visible;
                ActivationScreen.ActivationArea.Visibility = Visibility.Visible;
                ActivationScreen.customerKey.Focus();
                ActivationScreen.Close.Visibility = Visibility.Visible;
                ActivationScreen.showActivation(this);
                ShowModal();
            }
        }

        private void DoActivateClose(bool isComplete)
        {
            DoubleAnimation animation = new DoubleAnimation(0, TimeSpan.FromSeconds(.3));
            ThicknessAnimation animateThick = new ThicknessAnimation(new Thickness(0, 0, 0, 0), TimeSpan.FromSeconds(.3));
            animation.Completed += CloseComplete;
            ActivationScreen.BeginAnimation(Grid.OpacityProperty, animation);
            ActivationScreen.BeginAnimation(Grid.MarginProperty, animateThick);
            HideModal();
            StartUpdateActivationButtonLoop(this.cancellationActivationToken.Token);
        }

        private async void StartUpdateActivationButtonLoop(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                if (!Dispatcher.CheckAccess())
                {
                    // Ensure UI updates are performed on the UI thread
                    Dispatcher.Invoke(() => UpdateButtonContent());
                }
                else
                {
                    UpdateButtonContent();
                }

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

        private void UpdateButtonContent()
        {
            if (ProxyWatchdog.Shared.IsRegistered)
            {
                MainUI.ActivationButton.Content = "Shield Dashboard";
            }
            else if (!ProxyWatchdog.Shared.IsRegistered && ProxyWatchdog.Shared.IsRunning)
            {
                MainUI.ActivationButton.Content = "Activate Shield";
            }
            else 
            {
                MainUI.ActivationButton.Content = "Shield Unavailable";
            }
        }

        protected override void OnClosed(EventArgs e)
        {
            base.OnClosed(e);
            this.cancellationActivationToken.Cancel(); // Cancel the loop on window close
        }

        private System.Windows.Forms.ContextMenu contextMenu;
		private System.Windows.Forms.MenuItem contextMenuItem;
		private System.ComponentModel.IContainer components;
		public MainWindow() {
			InitializeComponent();
			SystemEvents.DisplaySettingsChanged += SystemEvents_DisplaySettingsChanged;
			string nlogFile = Path.Combine(ExecutionDirectory, ThisAssemblyName + "-log.config");

			ToastNotificationManagerCompat.OnActivated += ToastNotificationManagerCompat_OnActivated;

			bool byFile = false;
			if (File.Exists(nlogFile)) {
				LogManager.Configuration = new XmlLoggingConfiguration(nlogFile);
				byFile = true;
			} else {
				var config = new LoggingConfiguration();
				// Targets where to log to: File and Console
				var logfile = new FileTarget("logfile") {
					FileName = ExpectedLogPathUI,
					ArchiveEvery = FileArchivePeriod.Day,
					ArchiveNumbering = ArchiveNumberingMode.Rolling,
					MaxArchiveFiles = 7,
					Layout = "[${date:format=yyyy-MM-ddTHH:mm:ss.fff}Z] ${level:uppercase=true:padding=5}\t${logger}\t${message}\t${exception:format=tostring}",
				};
				var logconsole = new ConsoleTarget("logconsole");

				// Rules for mapping loggers to targets            
				config.AddRule(LogLevel.Debug, LogLevel.Fatal, logconsole);
				config.AddRule(LogLevel.Debug, LogLevel.Fatal, logfile);

				// Apply config           
				LogManager.Configuration = config;
			}
			logger.Info("============================== UI started ==============================");
			logger.Info("logger initialized");
			logger.Info("    - version   : {0}", asm.GetName().Version.ToString());
			logger.Info("    - using file: {0}", byFile);
			logger.Info("========================================================================");

			App.Current.MainWindow.WindowState = WindowState.Normal;
			App.Current.MainWindow.Deactivated += MainWindow_Deactivated;
			App.Current.MainWindow.Activated += MainWindow_Activated;
			App.Current.Exit += Current_Exit;
			App.Current.SessionEnding += Current_SessionEnding;


			this.components = new System.ComponentModel.Container();
			this.contextMenu = new System.Windows.Forms.ContextMenu();
			this.contextMenuItem = new System.Windows.Forms.MenuItem();
			this.contextMenu.MenuItems.AddRange(new System.Windows.Forms.MenuItem[] { this.contextMenuItem });

			this.contextMenuItem.Index = 0;
			this.contextMenuItem.Text = "&Close UI";
			this.contextMenuItem.Click += new System.EventHandler(this.contextMenuItem_Click);


			notifyIcon = new System.Windows.Forms.NotifyIcon();
			notifyIcon.Visible = true;
			notifyIcon.Click += TargetNotifyIcon_Click;
			notifyIcon.Visible = true;
			notifyIcon.BalloonTipClosed += NotifyIcon_BalloonTipClosed;
			notifyIcon.MouseClick += NotifyIcon_MouseClick;
			notifyIcon.ContextMenu = this.contextMenu;

			IdentityMenu.OnDetach += OnDetach;
			MainMenu.OnDetach += OnDetach;

			this.MainMenu.MainWindow = this;
			this.IdentityMenu.MainWindow = this;
			SetNotifyIcon("white");

			this.PreviewKeyDown += KeyPressed;
			MFASetup.OnLoad += MFASetup_OnLoad;
			MFASetup.OnError += MFASetup_OnError;
			IdentityMenu.OnMessage += IdentityMenu_OnMessage;

			ProxyWatchdog.Shared = new ProxyWatchdog();
			ProxyWatchdog.Shared.Start();

            this.cancellationActivationToken = new CancellationTokenSource();
            StartUpdateActivationButtonLoop(cancellationActivationToken.Token);
        }

		async private void MFASetup_OnError(string message) {
			await ShowBlurbAsync(message, "", "error");
		}

		private void ToastNotificationManagerCompat_OnActivated(ToastNotificationActivatedEventArgsCompat e) {
			this.Dispatcher.Invoke(() => {
				if (e.Argument != null && e.Argument.Length > 0) {
					string[] items = e.Argument.Split(';');
					if (items.Length > 0) {
						string[] values = items[0].Split('=');
						if (values.Length == 2) {
							string identifier = values[1];
							for (int i = 0; i < identities.Count; i++) {
								if (identities[i].Identifier == identifier) {
									ShowMFA(identities[i], 1);
									break;
								}
							}
						}
					}
				}
			});
		}

		private void KeyPressed(object sender, KeyEventArgs e) {
			if (e.Key == Key.Escape) {
				if (IdentityMenu.Visibility == Visibility.Visible) IdentityMenu.Visibility = Visibility.Collapsed;
				else if (MainMenu.Visibility == Visibility.Visible) MainMenu.Visibility = Visibility.Collapsed;
			}
		}

		private void MFASetup_OnLoad(bool isComplete, string title, string message) {
			if (isComplete) HideLoad();
			else ShowLoad(title, message);
		}

		private void Current_SessionEnding(object sender, SessionEndingCancelEventArgs e) {
			if (notifyIcon != null) {
				notifyIcon.Visible = false;
				notifyIcon.Icon.Dispose();
				notifyIcon.Dispose();
				notifyIcon = null;
			}
			Application.Current.Shutdown();
		}

		private void Current_Exit(object sender, ExitEventArgs e) {
			if (notifyIcon != null) {
				notifyIcon.Visible = false;
				notifyIcon.Icon.Dispose();
				notifyIcon.Dispose();
				notifyIcon = null;
			}
		}

		private void contextMenuItem_Click(object Sender, EventArgs e) {
			Application.Current.Shutdown();
		}

		private void NotifyIcon_MouseClick(object sender, System.Windows.Forms.MouseEventArgs e) {
			if (e.Button == System.Windows.Forms.MouseButtons.Left) {
				System.Windows.Forms.MouseEventArgs mea = (System.Windows.Forms.MouseEventArgs)e;
				this.Show();
				this.Activate();
				//Do the awesome left clickness
			} else if (e.Button == System.Windows.Forms.MouseButtons.Right) {
				//Do the wickedy right clickness
			} else {
				//Some other button from the enum :)
			}
		}

        private void NotifyIcon_BalloonTipClosed(object sender, EventArgs e) {
			var thisIcon = (System.Windows.Forms.NotifyIcon)sender;
			thisIcon.Visible = false;
			thisIcon.Dispose();
		}

        private void Window_MouseDown(object sender, MouseButtonEventArgs e) {
			OnDetach(e);
		}

		private void OnDetach(MouseButtonEventArgs e) {
			if (e.ChangedButton == MouseButton.Left) {
				_isAttached = false;
				IdentityMenu.Arrow.Visibility = Visibility.Collapsed;
				Arrow.Visibility = Visibility.Collapsed;
				MainMenu.Detach();
				this.DragMove();
			}
		}

		private void MainWindow_Activated(object sender, EventArgs e) {
			Placement();
			this.Show();
			this.Visibility = Visibility.Visible;
			this.Opacity = 1;
		}

		private void MainWindow_Deactivated(object sender, EventArgs e) {
			if (this._isAttached) {
				this.Visibility = Visibility.Hidden;
			}
		}

		private void MainWindow_Closing(object sender, System.ComponentModel.CancelEventArgs e) {
			if (notifyIcon != null) {
				notifyIcon.Visible = false;
				notifyIcon.Icon.Dispose();
				notifyIcon.Dispose();
				notifyIcon = null;
			}
			Application.Current.Shutdown();
		}

		private void SetCantDisplay(string title, string detailMessage, Visibility closeButtonVisibility) {
			this.Dispatcher.Invoke(() => {
				NoServiceView.Visibility = Visibility.Visible;
				CloseErrorButton.IsEnabled = true;
				CloseErrorButton.Visibility = closeButtonVisibility;
				ErrorMsg.Content = title;
				ErrorMsgDetail.Content = detailMessage;
				SetNotifyIcon("red");
				_isServiceInError = true;
				UpdateServiceView();
			});
		}

		private void TargetNotifyIcon_Click(object sender, EventArgs e) {
			this.Show();
			this.Activate();
			Application.Current.MainWindow.Activate();
		}

		private void UpdateServiceView() {
			if (_isServiceInError) {
				AddIdAreaButton.Opacity = 0.1;
				AddIdAreaButton.IsEnabled = false;
				//AddIdButton.Opacity = 0.1;
				//AddIdButton.IsEnabled = false;
				ConnectButton.Opacity = 0.1;
			} else {
				AddIdAreaButton.Opacity = 1.0;
				AddIdAreaButton.IsEnabled = true;
				//AddIdButton.Opacity = 1.0;
				//AddIdButton.IsEnabled = true;
				ConnectButton.Opacity = 1.0;
			}
			TunnelConnected(!_isServiceInError);
		}

		private void App_ReceiveString(string obj) {
			Console.WriteLine(obj);
			this.Show();
			this.Activate();
		}

		async private void MainWindow_Loaded(object sender, RoutedEventArgs e) {

			Window window = Window.GetWindow(App.Current.MainWindow);
			ZitiDesktopEdge.App app = (ZitiDesktopEdge.App)App.Current;
			app.ReceiveString += App_ReceiveString;

			// add a new service client
			serviceClient = new DataClient("ui");
			serviceClient.OnClientConnected += ServiceClient_OnClientConnected;
			serviceClient.OnClientDisconnected += ServiceClient_OnClientDisconnected;
			serviceClient.OnIdentityEvent += ServiceClient_OnIdentityEvent;
			serviceClient.OnMetricsEvent += ServiceClient_OnMetricsEvent;
			serviceClient.OnServiceEvent += ServiceClient_OnServiceEvent;
			serviceClient.OnTunnelStatusEvent += ServiceClient_OnTunnelStatusEvent;
			serviceClient.OnMfaEvent += ServiceClient_OnMfaEvent;
			serviceClient.OnLogLevelEvent += ServiceClient_OnLogLevelEvent;
			serviceClient.OnBulkServiceEvent += ServiceClient_OnBulkServiceEvent;
			serviceClient.OnNotificationEvent += ServiceClient_OnNotificationEvent;
			serviceClient.OnControllerEvent += ServiceClient_OnControllerEvent;
			Application.Current.Properties.Add("ServiceClient", serviceClient);

			monitorClient = new MonitorClient("ui");
			monitorClient.OnClientConnected += MonitorClient_OnClientConnected;
			monitorClient.OnNotificationEvent += MonitorClient_OnInstallationNotificationEvent;
            monitorClient.OnServiceStatusEvent += MonitorClient_OnServiceStatusEvent;
            monitorClient.OnShutdownEvent += MonitorClient_OnShutdownEvent;
			monitorClient.OnCommunicationError += MonitorClient_OnCommunicationError;
            monitorClient.OnReconnectFailure += MonitorClient_OnReconnectFailure;
			Application.Current.Properties.Add("MonitorClient", monitorClient);

			Application.Current.Properties.Add("Identities", new List<ZitiIdentity>());
			MainMenu.OnAttachmentChange += AttachmentChanged;
			MainMenu.OnLogLevelChanged += LogLevelChanged;
			MainMenu.OnShowBlurb += MainMenu_OnShowBlurb;
			IdentityMenu.OnError += IdentityMenu_OnError;

			try {
				await serviceClient.ConnectAsync();
				await serviceClient.WaitForConnectionAsync();
			} catch /*ignored for now (Exception ex) */{
				ShowServiceNotStarted();
				serviceClient.Reconnect();
			}

			try {
				await monitorClient.ConnectAsync();
				await monitorClient.WaitForConnectionAsync();
			} catch /*ignored for now (Exception ex) */{
				monitorClient.Reconnect();
			}

			IdentityMenu.OnForgot += IdentityForgotten;
			Placement();
		}

		private void MonitorClient_OnCommunicationError(object sender, Exception e) {
			string msg = "Communication Error with monitor?";
			ShowError(msg, e.Message);
		}

		private void MainMenu_OnShowBlurb(string message) {
			_ = ShowBlurbAsync(message, "", "info");
		}

		private void ServiceClient_OnBulkServiceEvent(object sender, BulkServiceEvent e) {
			var found = identities.Find(id => id.Identifier == e.Identifier);
			if (found == null) {
				logger.Warn($"{e.Action} service event for {e.Identifier} but the provided identity identifier was not found!");
				return;
			} else {
				if (e.RemovedServices != null) {
					foreach (var removed in e.RemovedServices) {
						removeService(found, removed);
					}
				}
				if (e.AddedServices != null) {
					foreach (var added in e.AddedServices) {
						addService(found, added);
					}
				}
				LoadIdentities(true);
				this.Dispatcher.Invoke(() => {
					IdentityDetails deets = ((MainWindow)Application.Current.MainWindow).IdentityMenu;
					if (deets.IsVisible) {
						deets.UpdateView();
					}
				});
			}
		}

		private void ServiceClient_OnNotificationEvent(object sender, NotificationEvent e) {
			var displayMFARequired = false;
			var displayMFATimout = false;
			foreach (var notification in e.Notification) {
				var found = identities.Find(id => id.Identifier == notification.Identifier);
				if (found == null) {
					logger.Warn($"{e.Op} event for {notification.Identifier} but the provided identity identifier was not found!");
					continue;
				} else {
					found.TimeoutMessage = notification.Message;
					found.MaxTimeout = notification.MfaMaximumTimeout;
					found.MinTimeout = notification.MfaMinimumTimeout;

					if (notification.MfaMinimumTimeout == 0) {
						// found.MFAInfo.IsAuthenticated = false;
						// display mfa token icon
						displayMFARequired = true;
					} else {
						displayMFATimout = true;
					}

					for (int i = 0; i < identities.Count; i++) {
						if (identities[i].Identifier == found.Identifier) {
							identities[i] = found;
							break;
						}
					}
				}
			}

			// we may need to display mfa icon, based on the timer in UI, remove found.MFAInfo.IsAuthenticated setting in this function. 
			// the below function can show mfa icon even after user authenticates successfully, in race conditions
			if (displayMFARequired || displayMFATimout) {
				this.Dispatcher.Invoke(() => {
					IdentityDetails deets = ((MainWindow)Application.Current.MainWindow).IdentityMenu;
					if (deets.IsVisible) {
						deets.UpdateView();
					}
				});
			}
			LoadIdentities(true);
		}

		private void ServiceClient_OnControllerEvent(object sender, ControllerEvent e) {
			logger.Debug($"==== ControllerEvent    : action:{e.Action} identifier:{e.Identifier}");
			// commenting this block, because when it receives the disconnected events, identities are disabled and
			// it is not allowing me to click/perform any operation on the identity
			// the color of the title is also too dark, and it is not clearly visible, when the identity is disconnected 
			/* if (e.Action == "connected") {
				var found = identities.Find(i => i.Identifier == e.Identifier);
				found.IsConnected = true;
				for (int i = 0; i < identities.Count; i++) {
					if (identities[i].Identifier == found.Identifier) {
						identities[i] = found;
						break;
					}
				}
				LoadIdentities(true);
			} else if (e.Action == "disconnected") {
				var found = identities.Find(i => i.Identifier == e.Identifier);
				found.IsConnected = false;
				for (int i = 0; i < identities.Count; i++) {
					if (identities[i].Identifier == found.Identifier) {
						identities[i] = found;
						break;
					}
				}
				LoadIdentities(true);
			} */
		}


		string nextVersionStr  = null;
        private void MonitorClient_OnReconnectFailure(object sender, object e) {
			logger.Debug("OnReconnectFailure triggered");
			if (nextVersionStr == null) {
				// check for the current version
				nextVersionStr = "checking for update";
				Version nextVersion = VersionUtil.NormalizeVersion(GithubAPI.GetVersion(GithubAPI.GetJson(GithubAPI.ProdUrl)));
				nextVersionStr = nextVersion.ToString();
				Version currentVersion = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version; //fetch from ziti?

				int compare = currentVersion.CompareTo(nextVersion);
				if (compare < 0) {
					MainMenu.SetAppUpgradeAvailableText("Upgrade available: " + nextVersionStr);
					logger.Info("upgrade is available. Published version: {} is newer than the current version: {}", nextVersion, currentVersion);
					//UpgradeAvailable();
				} else if (compare > 0) {
					logger.Info("the version installed: {0} is newer than the released version: {1}", currentVersion, nextVersion);
					MainMenu.SetAppIsNewer("This version is newer than the latest: " + nextVersionStr);
				} else {
					logger.Info("Current version installed: {0} is the same as the latest released version {1}", currentVersion, nextVersion);
					MainMenu.SetAppUpgradeAvailableText("");
				}
			}
        }

        private void MonitorClient_OnShutdownEvent(object sender, StatusEvent e)
		{
			logger.Info("The monitor has indicated the application should shut down.");
			this.Dispatcher.Invoke(() => {
				Application.Current.Shutdown();
			});
		}

		private void MonitorClient_OnServiceStatusEvent(object sender, MonitorServiceStatusEvent evt) {
			try {
				if (evt.Message?.ToLower() == "upgrading") {
					logger.Info("The monitor has indicated an upgrade is in progress. Shutting down the UI");
					notifyIcon.Visible = false;
					notifyIcon.Icon.Dispose();
					notifyIcon.Dispose();
					Application.Current.Shutdown();
				}
				state.AutomaticUpdatesEnabledFromString(evt.AutomaticUpgradeDisabled);
				MainMenu.ShowUpdateAvailable();
				logger.Debug("MonitorClient_OnServiceStatusEvent: {0}", evt.Status);
				Application.Current.Properties["ReleaseStream"] = evt.ReleaseStream;

				ServiceControllerStatus status = (ServiceControllerStatus)Enum.Parse(typeof(ServiceControllerStatus), evt.Status);

				switch (status) {
					case ServiceControllerStatus.Running:
						logger.Info("Service is started");
						break;
					case ServiceControllerStatus.Stopped:
						logger.Info("Service is stopped");
						ShowServiceNotStarted();
						break;
					case ServiceControllerStatus.StopPending:
						logger.Info("Service is stopping...");

						this.Dispatcher.Invoke(async () => {
							SetCantDisplay("The Service is Stopping", "Please wait while the service stops", Visibility.Hidden);
							await WaitForServiceToStop(DateTime.Now + TimeSpan.FromSeconds(30));
						});
						break;
					case ServiceControllerStatus.StartPending:
						logger.Info("Service is starting...");
						break;
					case ServiceControllerStatus.PausePending:
						logger.Warn("UNEXPECTED STATUS: PausePending");
						break;
					case ServiceControllerStatus.Paused:
						logger.Warn("UNEXPECTED STATUS: Paused");
						break;
					default:
						logger.Warn("UNEXPECTED STATUS: {0}", evt.Status);
						break;
				}
			} catch (Exception ex) {
				logger.Warn(ex, "unexpected exception in MonitorClient_OnShutdownEvent? {0}", ex.Message);
			}
		}

		private void MonitorClient_OnInstallationNotificationEvent(object sender, InstallationNotificationEvent evt) {
			this.Dispatcher.Invoke(() => {
				logger.Debug("MonitorClient_OnInstallationNotificationEvent: {0}", evt.Message);

				if ("installationupdate".Equals(evt.Message?.ToLower()) || "Configuration Changed" == evt.Message) {
					logger.Debug("Installation Update is available - {0}", evt.ZDEVersion);
					IsUpdateAvailable = true;
					var remaining = evt.InstallTime - DateTime.Now;

					state.AutomaticUpdatesEnabledFromString(evt.AutomaticUpgradeDisabled);
					state.PendingUpdate.Version = evt.ZDEVersion;
					state.PendingUpdate.InstallTime = evt.InstallTime;
					MainMenu.ShowUpdateAvailable();
					AlertCanvas.Visibility = Visibility.Visible;

					if (isToastEnabled()) {
						if (!state.AutomaticUpdatesDisabled) {
							if (remaining.TotalSeconds < 60) {
								//this is an immediate update - show a different message
								ShowToast("Ziti Desktop Edge will initiate auto installation in the next minute!");
							} else {
								ShowToast($"Update {evt.ZDEVersion} is available for Ziti Desktop Edge and will be automatically installed by " + evt.InstallTime);
							}
						} else {
							ShowToast($"Version {evt.ZDEVersion} is available for Ziti Desktop Edge");
						}
						SetNotifyIcon("");
						// display a tag in UI and a button for the update software
					}
				}
			});
		}

		public bool isToastEnabled() {
			bool result;
			//only show notifications once if automatic updates are disabled
			if (NotificationsShownCount == 0) {
				result = true; //regardless - if never notified, always return true
			} else {
				result = !state.AutomaticUpdatesDisabled;
			}
			return result;
		}

		public void ShowToast(string message) {
			new ToastContentBuilder()
				.AddText("Important Notice")
				.AddText(message)
				.SetBackgroundActivation()
				.Show();
			NotificationsShownCount++;
		}

		async private Task WaitForServiceToStop(DateTime until) {
			//continually poll for the service to stop. If it is stuck - ask the user if they want to try to force
			//close the service
			while (DateTime.Now < until) {
				await Task.Delay(2000);
				MonitorServiceStatusEvent resp = await monitorClient.StatusAsync();
				if (resp.IsStopped()) {
					// good - that's what we are waiting for...
					return;
				} else {
					// bad - not stopped yet...
					logger.Debug("Waiting for service to stop... Still not stopped yet. Status: {0}", resp.Status);
				}
			}
			// real bad - means it's stuck probably. Ask the user if they want to try to force it...
			logger.Warn("Waiting for service to stop... Service did not reach stopped state in the expected amount of time.");
			SetCantDisplay("The Service Appears Stuck", "Would you like to try to force close the service?", Visibility.Visible);
			CloseErrorButton.Content = "Force Quit";
			CloseErrorButton.Click -= CloseError;
			CloseErrorButton.Click += ForceQuitButtonClick;
		}

		async private void ForceQuitButtonClick(object sender, RoutedEventArgs e) {
			MonitorServiceStatusEvent status = await monitorClient.ForceTerminateAsync();
			if (status.IsStopped()) {
				//good
				CloseErrorButton.Click += CloseError; //reset the close button...
				CloseErrorButton.Click -= ForceQuitButtonClick;
			} else {
				//bad...
				SetCantDisplay("The Service Is Still Running", "Current status is: " + status.Status, Visibility.Visible);
			}
		}

		async private void StartZitiService(object sender, RoutedEventArgs e) {
			try {
				ShowLoad("Starting", "Starting the data service");
				logger.Info("StartZitiService");
				var r = await monitorClient.StartServiceAsync();
				if (r.Code != 0) {
					logger.Debug("ERROR: {0} : {1}", r.Message, r.Error);
				} else {
					logger.Info("Service started!");
					//no longer used: startZitiButtonVisible = false;
					CloseErrorButton.Click -= StartZitiService;
					CloseError(null, null);
				}
			} catch (Exception ex) {
				logger.Info(ex, "UNEXPECTED ERROR!");
				//no longer used: startZitiButtonVisible = false;
				//CloseErrorButton.Click += StartZitiService;
				CloseErrorButton.IsEnabled = true;
			}
			CloseErrorButton.IsEnabled = true;
			// HideLoad();
		}

		private void ShowServiceNotStarted() {
			TunnelConnected(false);
			LoadIdentities(true);
			/*
			this.Dispatcher.Invoke(() => {
				semaphoreSlim.Wait(); //make sure the event is only added to the button once
				CloseErrorButton.Click -= CloseError;
				if (!startZitiButtonVisible) {
					CloseErrorButton.Content = "Start Service";
					startZitiButtonVisible = true;
					CloseErrorButton.Click += StartZitiService;
				}
				semaphoreSlim.Release();
				SetCantDisplay("Service Not Started", "Do you want to start the data service now?", Visibility.Visible);
			});
			*/
		}

		private void MonitorClient_OnClientConnected(object sender, object e) {
			logger.Debug("MonitorClient_OnClientConnected");
			MainMenu.SetAppUpgradeAvailableText("");
		}

		async private void LogLevelChanged(string level) {
			await serviceClient.SetLogLevelAsync(level);
			await monitorClient.SetLogLevelAsync(level);
			Ziti.Desktop.Edge.Utils.UIUtils.SetLogLevel(level);
		}

		private void IdentityMenu_OnError(string message) {
			ShowError("Identity Error", message);
		}

		private void ServiceClient_OnClientConnected(object sender, object e) {
			this.Dispatcher.Invoke(() => {
				MainMenu.Connected();
				NoServiceView.Visibility = Visibility.Collapsed;
				_isServiceInError = false;
				UpdateServiceView();
				SetNotifyIcon("white");
				LoadIdentities(true);
			});
		}

		private void ServiceClient_OnClientDisconnected(object sender, object e) {
			this.Dispatcher.Invoke(() => {
				IdentityMenu.Visibility = Visibility.Collapsed;
				MFASetup.Visibility = Visibility.Collapsed;
				HideModal();
				MainMenu.Disconnected();
				for (int i = 0; i < IdList.Children.Count; i++) {
					IdentityItem item = (IdentityItem)IdList.Children[i];
					item.StopTimers();
				}
				IdList.Children.Clear();
				if (e != null) {
					logger.Debug(e.ToString());
				}
				//SetCantDisplay("Start the Ziti Tunnel Service to continue");
				ShowServiceNotStarted();
			});
		}

		/// <summary>
		/// If an identity gets added late, execute this.
		/// 
		/// Do not update services for identity events
		/// </summary>
		/// <param name="sender">The sending service</param>
		/// <param name="e">The identity event</param>
		private void ServiceClient_OnIdentityEvent(object sender, IdentityEvent e) {
			if (e == null) return;

			ZitiIdentity zid = ZitiIdentity.FromClient(e.Id);
			logger.Debug($"==== IdentityEvent    : action:{e.Action} identifer:{e.Id.Identifier} name:{e.Id.Name} ");

			this.Dispatcher.Invoke(async () => {
				if (e.Action == "added") {
					var found = identities.Find(i => i.Identifier == e.Id.Identifier);
					if (found == null) {
						AddIdentity(zid);
						LoadIdentities(true);
					} else {
						// means we likely are getting an update for some reason. compare the identities and use the latest info
						if (zid.Name!=null && zid.Name.Length>0) found.Name = zid.Name;
						if (zid.ControllerUrl != null && zid.ControllerUrl.Length > 0) found.ControllerUrl = zid.ControllerUrl;
						if (zid.ContollerVersion != null && zid.ContollerVersion.Length > 0) found.ContollerVersion = zid.ContollerVersion;
						found.IsEnabled = zid.IsEnabled;
						found.IsMFAEnabled = e.Id.MfaEnabled;
						found.IsAuthenticated = !e.Id.MfaNeeded;
						found.IsConnected = true;
						for (int i=0; i<identities.Count; i++) {
							if (identities[i].Identifier == found.Identifier) {
								identities[i] = found;
								break;
							}
						}
						LoadIdentities(true);
					}
				} else if (e.Action == "updated") {
					//this indicates that all updates have been sent to the UI... wait for 2 seconds then trigger any ui updates needed
					await Task.Delay(2000);
					LoadIdentities(true);
				} else if (e.Action == "connected") {
					var found = identities.Find(i => i.Identifier == e.Id.Identifier);
					found.IsConnected = true;
					for (int i = 0; i < identities.Count; i++) {
						if (identities[i].Identifier == found.Identifier) {
							identities[i] = found;
							break;
						}
					}
					LoadIdentities(true);
				} else if (e.Action == "disconnected") {
					var found = identities.Find(i => i.Identifier == e.Id.Identifier);
					found.IsConnected = false;
					for (int i = 0; i < identities.Count; i++) {
						if (identities[i].Identifier == found.Identifier) {
							identities[i] = found;
							break;
						}
					}
					LoadIdentities(true);
				} else {
					IdentityForgotten(ZitiIdentity.FromClient(e.Id));
				}
			});
			logger.Debug($"IDENTITY EVENT. Action: {e.Action} identifier: {zid.Identifier}");
		}

		private void ServiceClient_OnMetricsEvent(object sender, List<Identity> ids) {
			if (ids != null) {
				long totalUp = 0;
				long totalDown = 0;
				foreach (var id in ids) {
					//logger.Debug($"==== MetricsEvent     : id {id.Name} down: {id.Metrics.Down} up:{id.Metrics.Up}");
					if (id?.Metrics != null) {
						totalDown += id.Metrics.Down;
						totalUp += id.Metrics.Up;
					}
				}
			}
		}

		public void SetSpeed(decimal bytes, Label speed, Label speedLabel) {
			int counter = 0;
			while (Math.Round(bytes / 1024) >= 1) {
				bytes = bytes / 1024;
				counter++;
			}
			speed.Content = bytes.ToString("0.0");
			speedLabel.Content = suffixes[counter];
		}

		private void ServiceClient_OnServiceEvent(object sender, ServiceEvent e) {
			if (e == null) return;

			logger.Debug($"==== ServiceEvent     : action:{e.Action} identifier:{e.Identifier} name:{e.Service.Name} ");
			var found = identities.Find(id => id.Identifier == e.Identifier);
			if (found == null) {
				logger.Debug($"{e.Action} service event for {e.Service.Name} but the provided identity identifier {e.Identifier} is not found!");
				return;
			}

			if (e.Action == "added") {
				addService(found, e.Service);
			} else {
				removeService(found, e.Service);
			}
			LoadIdentities(true);
			this.Dispatcher.Invoke(() => {
				IdentityDetails deets = ((MainWindow)Application.Current.MainWindow).IdentityMenu;
				if (deets.IsVisible) {
					deets.UpdateView();
				}
			});
		}

		private void addService(ZitiIdentity found, Service added) {
			ZitiService zs = new ZitiService(added);
			var svc = found.Services.Find(s => s.Name == zs.Name);
			if (svc == null) {
				logger.Debug("Service Added: " + zs.Name);
				found.Services.Add(zs);
				if (zs.HasFailingPostureCheck()) {
					found.HasServiceFailingPostureCheck = true;
					if (zs.PostureChecks.Any(p => !p.IsPassing && p.QueryType == "MFA")) {
						found.IsAuthenticated = false;
					}
				}
			} else {
				logger.Debug("the service named " + zs.Name + " is already accounted for on this identity.");
			}
		}

		private void removeService(ZitiIdentity found, Service removed) {
			logger.Debug("removing the service named: {0}", removed.Name);
			found.Services.RemoveAll(s => s.Name == removed.Name);
		}

		private void ServiceClient_OnTunnelStatusEvent(object sender, TunnelStatusEvent e) {
			if (e == null) return; //just skip it for now...
			logger.Debug($"==== TunnelStatusEvent: ");
			Application.Current.Properties.Remove("CurrentTunnelStatus");
			Application.Current.Properties.Add("CurrentTunnelStatus", e.Status);
			e.Status.Dump(Console.Out);
			this.Dispatcher.Invoke(() => {
				/*if (e.ApiVersion != DataClient.EXPECTED_API_VERSION) {
					SetCantDisplay("Version mismatch!", "The version of the Service is not compatible", Visibility.Visible);
					return;
				}*/
				this.MainMenu.LogLevel = e.Status.LogLevel;
				Ziti.Desktop.Edge.Utils.UIUtils.SetLogLevel(e.Status.LogLevel);

				InitializeTimer((int)e.Status.Duration);
				LoadStatusFromService(e.Status);
				LoadIdentities(true);
				IdentityDetails deets = ((MainWindow)Application.Current.MainWindow).IdentityMenu;
				if (deets.IsVisible) {
					deets.UpdateView();
				}
			});
		}
        
        private void ServiceClient_OnLogLevelEvent(object sender, LogLevelEvent e) {
            if (e.LogLevel != null) {
                SetLogLevel_monitor(e.LogLevel);
                this.Dispatcher.Invoke(() =>  {
                    this.MainMenu.LogLevel = e.LogLevel;
                    Ziti.Desktop.Edge.Utils.UIUtils.SetLogLevel(e.LogLevel);
                });
            }
        }

        async private void SetLogLevel_monitor(string loglevel)  {
            await monitorClient.SetLogLevelAsync(loglevel);
        }

		private void IdentityForgotten(ZitiIdentity forgotten) {
			ZitiIdentity idToRemove = null;
			foreach (var id in identities) {
				if (id.Identifier == forgotten.Identifier) {
					idToRemove = id;
					break;
				}
			}
			identities.Remove(idToRemove);
			LoadIdentities(false);
		}

		private void AttachmentChanged(bool attached) {
			_isAttached = attached;
			if (!_isAttached) {
				SetLocation();
			}
			Placement();
			MainMenu.Visibility = Visibility.Collapsed;
		}

		private void LoadStatusFromService(TunnelStatus status) {
			//clear any identities
			this.identities.Clear();

			if (status != null) {
				_isServiceInError = false;
				UpdateServiceView();
				NoServiceView.Visibility = Visibility.Collapsed;
				if (status.Active) {
					SetNotifyIcon("green");
				} else {
					SetNotifyIcon("white");
				}
				if (!Application.Current.Properties.Contains("ip")) {
					Application.Current.Properties.Add("ip", status?.IpInfo?.Ip);
				} else {
					Application.Current.Properties["ip"] = status?.IpInfo?.Ip;
				}
				if (!Application.Current.Properties.Contains("subnet")) {
					Application.Current.Properties.Add("subnet", status?.IpInfo?.Subnet);
				} else {
					Application.Current.Properties["subnet"] = status?.IpInfo?.Subnet;
				}
				if (!Application.Current.Properties.Contains("mtu")) {
					Application.Current.Properties.Add("mtu", status?.IpInfo?.MTU);
				} else {
					Application.Current.Properties["mtu"] = status?.IpInfo?.MTU;
				}
				if (!Application.Current.Properties.Contains("dns")) {
					Application.Current.Properties.Add("dns", status?.IpInfo?.DNS);
				} else {
					Application.Current.Properties["dns"] = status?.IpInfo?.DNS;
				}
				if (!Application.Current.Properties.Contains("dnsenabled")) {
					Application.Current.Properties.Add("dnsenabled", status?.AddDns);
				} else {
					Application.Current.Properties["dnsenabled"] = status?.AddDns;
				}

				string key = "ApiPageSize";
				if (!Application.Current.Properties.Contains(key)) {
					Application.Current.Properties.Add(key, status?.ApiPageSize);
				} else {
					Application.Current.Properties[key] = status?.ApiPageSize;
				}

				foreach (var id in status.Identities) {
					updateViewWithIdentity(id);
				}
				LoadIdentities(true);
			} else {
				ShowServiceNotStarted();
			}
		}

		private void updateViewWithIdentity(Identity id) {
			var zid = ZitiIdentity.FromClient(id);
			foreach (var i in identities) {
				if (i.Identifier == zid.Identifier) {
					identities.Remove(i);
					break;
				}
			}
			identities.Add(zid);
		}

		private bool IsTimingOut() {
			if (identities!=null) {
				for (int i = 0; i < identities.Count; i++) {
					if (identities[i].IsTimingOut) return true;
				}
			}
			return false;
		}

		private bool IsTimedOut() {
			if (identities != null) {
				for (int i = 0; i < identities.Count; i++) {
					if (identities[i].IsMFAEnabled&&!identities[i].IsAuthenticated) return true;
				}
			}
			return false;
		}

		private void SetNotifyIcon(string iconPrefix) {
			if (iconPrefix != "") CurrentIcon = iconPrefix;
			string icon = "pack://application:,,/Assets/Images/ziti-" + CurrentIcon;
			if (IsUpdateAvailable) {
				icon += "-update";
			} else {
				if (IsTimedOut()) {
					icon += "-mfa";
				} else {
					if (IsTimingOut()) {
						icon += "-timer";
					}
				}
			}
			icon += ".ico";
			var iconUri = new Uri(icon);
			Stream iconStream = Application.GetResourceStream(iconUri).Stream;
			notifyIcon.Icon = new Icon(iconStream);

			Application.Current.MainWindow.Icon = System.Windows.Media.Imaging.BitmapFrame.Create(iconUri);
		}

		private void LoadIdentities(Boolean repaint) {
			this.Dispatcher.Invoke(() => {
				for (int i = 0; i < IdList.Children.Count; i++) {
					IdentityItem item = (IdentityItem)IdList.Children[i];
					item.StopTimers();
				}
				IdList.Children.Clear();
				IdList.Height = 0;
				var desktopWorkingArea = SystemParameters.WorkArea;
				if (_maxHeight > (desktopWorkingArea.Height - 10)) _maxHeight = desktopWorkingArea.Height - 10;
				if (_maxHeight < 100) _maxHeight = 100;
				IdList.MaxHeight = _maxHeight - 520;
				ZitiIdentity[] ids = identities.OrderBy(i => (i.Name != null) ? i.Name.ToLower() : i.Name).ToArray();
				MainMenu.SetupIdList(ids);
				if (ids.Length > 0 && serviceClient.Connected) {
					double height = 490 + (ids.Length * 60);
					if (height > _maxHeight) height = _maxHeight;
					this.Height = height;
					IdentityMenu.SetHeight(this.Height - 160);
					MainMenu.IdentitiesButton.Visibility = Visibility.Visible;
					foreach (var id in ids) {
						IdentityItem idItem = new IdentityItem();

						idItem.ToggleStatus.IsEnabled = id.IsEnabled;
						if (id.IsEnabled) idItem.ToggleStatus.Content = "ENABLED";
						else idItem.ToggleStatus.Content = "DISABLED";

						idItem.Authenticate += IdItem_Authenticate;
						idItem.OnStatusChanged += Id_OnStatusChanged;
						idItem.Identity = id;
						idItem.IdentityChanged += IdItem_IdentityChanged;
						
						if (repaint) idItem.RefreshUI();

						IdList.Children.Add(idItem);

						if (IdentityMenu.Visibility==Visibility.Visible) {
							if (id.Identifier == IdentityMenu.Identity.Identifier) IdentityMenu.Identity = id;
						}
					}
					DoubleAnimation animation = new DoubleAnimation((double)(ids.Length * 64), TimeSpan.FromSeconds(.2));
					IdList.BeginAnimation(FrameworkElement.HeightProperty, animation);
					IdListScroller.Visibility = Visibility.Visible;
				} else {
					this.Height = 490;
					MainMenu.IdentitiesButton.Visibility = Visibility.Collapsed;
					IdListScroller.Visibility = Visibility.Collapsed;
				}
				//AddIdButton.Visibility = Visibility.Visible;
				AddIdAreaButton.Visibility = Visibility.Visible;

				Placement();
				SetNotifyIcon("");
			});
		}

		private void IdItem_IdentityChanged(ZitiIdentity identity) {
			for (int i=0; i<identities.Count; i++) {
				if (identities[i].Identifier == identity.Identifier) {
					identities[i] = identity;
					break;
 				}
			}
			SetNotifyIcon("");
		}

		private void IdItem_Authenticate(ZitiIdentity identity) {
			ShowAuthenticate(identity);
		}

		private void Id_OnStatusChanged(bool attached) {
			for (int i = 0; i < IdList.Children.Count; i++) {
				IdentityItem item = IdList.Children[i] as IdentityItem;
				if (item.ToggleSwitch.Enabled) break;
			}
		}

		private void TunnelConnected(bool isConnected) {
			this.Dispatcher.Invoke(() => {
				if (isConnected) {
					ConnectButton.Visibility = Visibility.Collapsed;
					DisconnectButton.Visibility = Visibility.Visible;
                    ConnectedTime.Visibility = Visibility.Visible;
                    MainMenu.Connected();
					HideLoad();
				} else {
					ConnectButton.Visibility = Visibility.Visible;
					DisconnectButton.Visibility = Visibility.Collapsed;
					IdentityMenu.Visibility = Visibility.Collapsed;
					MainMenu.Visibility = Visibility.Collapsed;
					ConnectedTime.Visibility = Visibility.Collapsed;
                    HideBlurb();
					MainMenu.Disconnected();
				}
			});
		}

		private void SetLocation() {
			var desktopWorkingArea = SystemParameters.WorkArea;

			var height = MainView.ActualHeight;
			IdentityMenu.MainHeight = MainView.ActualHeight;
			MainMenu.MainHeight = MainView.ActualHeight;

			Rectangle trayRectangle = WinAPI.GetTrayRectangle();
			if (trayRectangle.Top < 20) {
				this.Position = "Top";
				this.Top = desktopWorkingArea.Top + _top;
				this.Left = desktopWorkingArea.Right - this.Width - _right;
				Arrow.SetValue(Canvas.TopProperty, (double)0);
				Arrow.SetValue(Canvas.LeftProperty, (double)185);
				MainMenu.Arrow.SetValue(Canvas.TopProperty, (double)0);
				MainMenu.Arrow.SetValue(Canvas.LeftProperty, (double)185);
				IdentityMenu.Arrow.SetValue(Canvas.TopProperty, (double)0);
				IdentityMenu.Arrow.SetValue(Canvas.LeftProperty, (double)185);
			} else if (trayRectangle.Left < 20) {
				this.Position = "Left";
				this.Left = _left;
				this.Top = desktopWorkingArea.Bottom - this.ActualHeight - 75;
				Arrow.SetValue(Canvas.TopProperty, height - 200);
				Arrow.SetValue(Canvas.LeftProperty, (double)0);
				MainMenu.Arrow.SetValue(Canvas.TopProperty, height - 200);
				MainMenu.Arrow.SetValue(Canvas.LeftProperty, (double)0);
				IdentityMenu.Arrow.SetValue(Canvas.TopProperty, height - 200);
				IdentityMenu.Arrow.SetValue(Canvas.LeftProperty, (double)0);
			} else if (desktopWorkingArea.Right == (double)trayRectangle.Left) {
				this.Position = "Right";
				this.Left = desktopWorkingArea.Right - this.Width - 20;
				this.Top = desktopWorkingArea.Bottom - height - 75;
				Arrow.SetValue(Canvas.TopProperty, height - 100);
				Arrow.SetValue(Canvas.LeftProperty, this.Width - 30);
				MainMenu.Arrow.SetValue(Canvas.TopProperty, height - 100);
				MainMenu.Arrow.SetValue(Canvas.LeftProperty, this.Width - 30);
				IdentityMenu.Arrow.SetValue(Canvas.TopProperty, height - 100);
				IdentityMenu.Arrow.SetValue(Canvas.LeftProperty, this.Width - 30);
			} else {
				this.Position = "Bottom";
				this.Left = desktopWorkingArea.Right - this.Width - 75;
				this.Top = desktopWorkingArea.Bottom - height;
				Arrow.SetValue(Canvas.TopProperty, height - 35);
				Arrow.SetValue(Canvas.LeftProperty, (double)185);
				MainMenu.Arrow.SetValue(Canvas.TopProperty, height - 35);
				MainMenu.Arrow.SetValue(Canvas.LeftProperty, (double)185);
				IdentityMenu.Arrow.SetValue(Canvas.TopProperty, height - 35);
				IdentityMenu.Arrow.SetValue(Canvas.LeftProperty, (double)185);
			}
		}
		public void Placement() {
			if (_isAttached) {
				Arrow.Visibility = Visibility.Visible;
				IdentityMenu.Arrow.Visibility = Visibility.Visible;
				SetLocation();
			} else {
				IdentityMenu.Arrow.Visibility = Visibility.Collapsed;
				Arrow.Visibility = Visibility.Collapsed;
			}
		}

		private void OpenIdentity(ZitiIdentity identity) {
			IdentityMenu.Identity = identity;
		}

		private void ShowMenu(object sender, MouseButtonEventArgs e) {
			MainMenu.Visibility = Visibility.Visible;
		}

        private void OpenIdentityChoice(object sender, MouseButtonEventArgs e)
        {
			logger.Info("Creating choice window...");
			try { 
				// Create the window
				var window = new Window
				{
					Title = "Select enrollment method",
					Width = 460,
					Height = 300,
					ResizeMode = ResizeMode.NoResize, // Disable allowing the user to resize the window
					WindowStartupLocation = WindowStartupLocation.CenterScreen, // Set startup location to center of screen
				};
				logger.Info("Window instance created...");

				// Create the radio buttons
				var radioButton1 = new RadioButton
				{
					Content = "Add identity via Azure Active Directory",
					FontSize = 16,
					Margin = new Thickness(10),
					IsChecked = true,
				};

				var radioButton1Text = new TextBlock
				{
					Text = "Select this option if this device has been connected to a work or school\naccount and your zero trust network supports automatic deployment via\nAzure Active Directory",
					FontSize = 12,
					Margin = new Thickness(25, 0, 10, 10),
					FontStyle = FontStyles.Italic
				};

				var radioButton2 = new RadioButton
				{
					Content = "Add identity from .jwt file",
					FontSize = 16,
					Margin = new Thickness(10)
				};

				var radioButton2Text = new TextBlock
				{
					Text = "Select this option if your network administrator has provided you a\n.JWT file",
					FontSize = 12,
					Margin = new Thickness(25, 0, 10, 10),
					FontStyle = FontStyles.Italic
				};

				// Create the buttons
				var buttonOk = new Button
				{
					Content = "OK",
					FontSize = 16,
					Margin = new Thickness(10, 10, 5, 10),
					Padding = new Thickness(5),
					IsDefault = true,
					MinWidth = 80
				};

				buttonOk.Click += (buttonSender, args) => window.DialogResult = true; // Add an event handler to close the window when the OK button is clicked

				var buttonCancel = new Button
				{
					Content = "Cancel",
					FontSize = 16,
					Margin = new Thickness(10, 10, 5, 10),
					Padding = new Thickness(5),
					MinWidth = 80,
					IsCancel = true
				};

				// Add the radio buttons and buttons to a stack panel
				var stackPanel = new StackPanel
				{
					Orientation = Orientation.Vertical, // Change to horizontal orientation
					Margin = new Thickness(10)
				};

				stackPanel.Children.Add(radioButton1);
				stackPanel.Children.Add(radioButton1Text);
				stackPanel.Children.Add(radioButton2);
				stackPanel.Children.Add(radioButton2Text);

				var buttonPanel = new StackPanel // Create a new stack panel for the buttons
				{
					Margin = new Thickness(10),
					Orientation = Orientation.Horizontal,
					HorizontalAlignment = HorizontalAlignment.Right // Center the buttons horizontally
				};

				buttonPanel.Children.Add(buttonOk);
				buttonPanel.Children.Add(buttonCancel);

				stackPanel.Children.Add(buttonPanel); // Add the button stack panel to the main stack panel

				// Set the content of the window to the stack panel
				window.Content = stackPanel;

				// Show the window and wait for it to be closed
				if (window.ShowDialog() == true)
				{
					// OK button was clicked
					if (radioButton1.IsChecked == true)
					{
						// Add Identity via Azure Active Directory
						AddIdentityViaAAD(sender, e);
					}
					else if (radioButton2.IsChecked == true)
					{
						// Add Identity from .jwt file
						AddIdentity(sender, e);
					}
				}
				else
				{
					// Cancel button was clicked or the window was closed
					// Do nothing
				}
			} catch (Exception ex)
			{
				logger.Error(ex);
			}
        }


        async private void AddIdentity(object sender, MouseButtonEventArgs e) {
			UIModel.HideOnLostFocus = false;
			Microsoft.Win32.OpenFileDialog jwtDialog = new Microsoft.Win32.OpenFileDialog();
			UIModel.HideOnLostFocus = true;
			jwtDialog.DefaultExt = ".jwt";
			jwtDialog.Filter = "Ziti Identities (*.jwt)|*.jwt";

			if (jwtDialog.ShowDialog() == true) {
				ShowLoad("Adding Identity", "Please wait while the identity is added");
				string fileContent = File.ReadAllText(jwtDialog.FileName);

				try {
					Identity createdId = await serviceClient.AddIdentityAsync(System.IO.Path.GetFileName(jwtDialog.FileName), false, fileContent);

					if (createdId != null) {
						var zid = ZitiIdentity.FromClient(createdId);
						AddIdentity(zid);
						MessageBox.Show("Loading identities");
						LoadIdentities(true);
						await serviceClient.IdentityOnOffAsync(createdId.Identifier, true);
					}/* else {
						ShowError("Identity Error", "Identity Id was null, please try again");
					}*/
				} catch (ServiceException se) {
					ShowError(se.Message, se.AdditionalInfo);
				} catch (Exception ex) {
					ShowError("Unexpected Error", "Code 2:" + ex.Message);
				}
				HideLoad();
			}
		}

        async private void AddIdentityViaAAD(object sender, MouseButtonEventArgs e)
        {
			// Verify that the device is registered, and get relevant info if so
			logger.Info("Getting the user's work domain...");

			var emailDomain = await GetEmailDomain();

			if (emailDomain is null)
			{
				logger.Warn("This computer is not associated with any Active Directory.");
                logger.Info("Showing message box...");
                //MessageBox.Show("This computer is not associated with any Active Directory.");
                return;
            }

			logger.Info("Encoding domain JWT...");
			var domainJWT = EncodeDomainJWT(emailDomain);

			logger.Info("Sending domain JWT to API to get config...");
			var configString = await SendDomainToken(domainJWT, testingEndpoint + "domains", testingAPIKey);

			if (configString is null)
			{
				return;
			}

			if (configString.Contains("404"))
			{
				logger.Error("Your workplace's domain isn't registered with Intrusion\nPlease contact your system administrator");
                //MessageBox.Show("Your workplace's domain isn't registered with Intrusion\nPlease contact your system administrator");
				return;
			}

            logger.Info("Config received: " + configString);
            //MessageBox.Show("Config received: " + configString);

            JObject configJson = JsonConvert.DeserializeObject<JObject>(configString);
			string encodedConfig = (string)configJson["jwt"];

            // Create a new instance of JwtSecurityTokenHandler
            var handler = new JwtSecurityTokenHandler();

            // Read and decode the JWT
            var jsonToken = handler.ReadToken(encodedConfig);
            var decodedJwt = jsonToken as JwtSecurityToken;

            // Access the JWT's claims
            string dom = decodedJwt.Claims.FirstOrDefault(claim => claim.Type == "dom")?.Value;
            // Base64url to Base64
            string base64 = dom.Replace('-', '+').Replace('_', '/');

            // Base64 to bytes
            byte[] bytes = Convert.FromBase64String(base64);

            // Bytes to string
            string json = System.Text.Encoding.UTF8.GetString(bytes);

            // Parse JSON string to object
            configJson = JsonConvert.DeserializeObject<JObject>(json);

			// Narrow down the results to just the key that contains the AAD config JSON
            JObject aadConfig = configJson.Value<JObject>("aad_configuration");

            logger.Info("Getting work account info...");
            //MessageBox.Show("Getting work account info...");

            var accountInfo = GetWorkAccountInfo();
            if (accountInfo == null || !(bool)accountInfo["WorkplaceJoined"])
            {
				logger.Warn("Showing message box...");
                MessageBox.Show("This computer is not associated with any Active Directory.");
                return;
            }

			// Start the Microsot SSO
			logger.Info("Starting Microsoft SSO...");
			AuthenticationHelper authHelper;
			string clientId = "";
			string authority;
			string[] scopes;
			string accessToken = "";
			try
			{
				authHelper = new AuthenticationHelper();
				clientId = (string)aadConfig["client_id"];
				authority = $"https://login.microsoftonline.com/{aadConfig["tenant_id"]}";
				//MessageBox.Show("Received scopes: " + aadConfig["scopes"]);
				//MessageBox.Show("Authority: " + authority + "\nclient ID: " + clientId);

                var arr = (JArray)aadConfig["scopes"];
                scopes = new string[arr.Count];

                //for (int i = 0; i < arr.Count; i++)
                //{
                //    scopes[i] = arr[i].ToString().Replace("User.ReadBasic.All", "User.Read.All").Replace(" ", "");
                //}


                scopes = new string[] { "Device.Read.All", "User.Read" };

                //MessageBox.Show("Processed scopes: " + string.Join(",", scopes));

                accessToken = await authHelper.AcquireAccessTokenAsync(clientId, authority, scopes);
			}
			catch (Exception ex)
			{
				logger.Error("Exception while starting SSO: " + ex.ToString());
				return;
			}
            ShowLoad("Adding Identity", "Please wait while the identity is added");
            logger.Info("Authentication success.");
            logger.Info("Getting UPN...");
            //MessageBox.Show("Getting UPN...");
            var upn = await GetUPN(accessToken);
            logger.Info("UPN received: " + upn);
            //MessageBox.Show("UPN received: " + upn);
            logger.Info("Getting Owned Devices list...");
            //MessageBox.Show("Getting Owned Devices list...");
            var devicesList = await GetOwnedDevices(accessToken);

            Dictionary<string, object> foundDevice = null;
            if (devicesList.Count == 0)
            {
				logger.Error("No devices found.");
                MessageBox.Show("Your Azure Active Directory account has no devices associated with it.");
                return;
            }
            else
            {
				// Run through the list of user's owned devices to find the one running the client
                foreach (var device in devicesList)
                {
                    if (device["deviceId"].Equals(accountInfo["WorkplaceDeviceId"]))
                    {
						logger.Info("Device match found.");
                        foundDevice = device;
                        break;
                    }
                }
            }

            if (foundDevice == null)
            {
				logger.Error("No device match found.");
                MessageBox.Show("No matching devices were found in your AAD account for this device.");
                return;
            }

            // Get external IP
            logger.Info("Getting external IP...");
            //MessageBox.Show("Getting external IP...");
            var ip = await GetCurrentExternalIPAsync();
			if (ip is null)
			{
				logger.Error("IP returned is null. API could be down, or no internet connection");
				MessageBox.Show("Unable to get your external IP.\nDo you have a working internet connection?");
				return;
			}
            logger.Info("External IP: " + ip);
            //MessageBox.Show("External IP: " + ip);

            string deviceID = (string)accountInfo["WorkplaceDeviceId"];
            string username = upn;
            string sourceIP = ip;
            string objectID = (string)foundDevice["id"];
            int expiryTime = 300;

            //MessageBox.Show("Encoding endpoint JWT token");
            string jwtToken = EncodeEndpointJwtToken(deviceID, username, sourceIP, objectID, expiryTime);

            logger.Info("Sending token to provisioning API...");
            //MessageBox.Show("Sending token to provisioning API...");
            var response = await SendToken(jwtToken, testingEndpoint + "endpoints", accessToken, testingAPIKey, deviceID);

            if (response == null)
            {
				logger.Error("No or invalid response from API. Closing load screen.");
                HideLoad();
                return;
            }

            logger.Info("Received JSON: " + response.ToString());
			//MessageBox.Show("Received JSON: " + response.ToString());

            // Deserialize the string into a JObject
            JObject jsonObject = JsonConvert.DeserializeObject<JObject>(response);
			string jwt = (string)jsonObject["jwt"];

            // TODO: Avoid creating a useless JWT file and send the response data directly to the AddIdentity

			// We currently have to write the received JWT to a file and import that using the normal AddIdentity option
			// The file is placed in the user's Documents folder, and deleted once it's used

            // Write received JWT to file
            string downloadsFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Personal));
            string fileName = Path.Combine(downloadsFolder, "AAD.jwt");
			try
			{
                File.WriteAllText(fileName, jwt);
                logger.Info("Written to " + fileName);
            }
			catch (Exception ex)
			{
				logger.Error("Error while writing file: " + ex.ToString());
				MessageBox.Show("Error while writing file: " + ex.ToString());
				return;
			}

            string fileContent = File.ReadAllText(fileName);
			logger.Info($"File Content:\n{fileContent}");

            try
            {
				logger.Info("Importing identity...");
				//MessageBox.Show("Importing identity");
                Identity createdId = await serviceClient.AddIdentityAsync(Path.GetFileName(fileName), false, fileContent);

                if (createdId != null)
                {
					logger.Info("Importing identity: " + createdId.ToString());
                    var zid = ZitiIdentity.FromClient(createdId);
                    AddIdentity(zid);
                    LoadIdentities(true);
                    await serviceClient.IdentityOnOffAsync(createdId.Identifier, true);
                }
            }
            catch (ServiceException se)
            {
				logger.Error(se.ToString());
                ShowError(se.Message, se.AdditionalInfo);
            }
            catch (Exception ex)
            {
				logger.Error(ex.ToString());
                ShowError("Unexpected Error", "Code 2: " + ex.Message);
            }
            HideLoad();
			logger.Info("Deleting file: " + fileName);
            File.Delete(fileName);

        }


        public static string EncodeDomainJWT(string domain, int expiryTime = 300)
		{
            logger.Info("Encrypting key...");

            string[] TOKEN_SIGNING_KEYS = new string[8]{
                "pĆȈ̈Ѝ՟؏ݘࠊ॓ਅ\u0b0dఅ\u0d50๐ཐၑᅊቍፉᐕᔚᘛᝊ᠙᥅ᩄᬓ᱁ᴖṁὀ‐K∧⌯\u242f┫♸✮⠯⤧⨯⬠ⱱ\u2d2b⸢⽰〤ㅪ㈿㌴㑩㔳㘸㜼㠻㤾㨵㭦㰳㵥㸱㼵",
                "yďȏ̉њ՝،܍࡞ॕਁ\u0b50ఁ\u0d55๐༄ၒᄜሟጛᑈᕍᘒᜑᡍᤑ᨟ᬑᰝᵂḒἔ⁄ℭ≻⌫\u242c╽♿❽⡺⥵⨣⬦Ⱒ\u2d71⸣⽷〠ㅪ㈼㍩㑪㕨㘹㜼㠾㥤㨵㭣㰲㵠㹣㼹",
                "rřȇ̅Ќ՘ٞ܁࡝॔ਃଆ౐ഊ๑བྷဇᄛቋፉᐙᔒᘓ᜛ᡉᤔ᨟ᬕ᱇ᵅṄἘ‗K∧⍻␫╿☬✡⠨⥱⨣⬢Ɒⴧ⸫⼩ふㄻ㉪㌵㐿㕯㙩㜸㠱㤶㩥㬱㰼㵢㸷㼸",
                "sĆȍ̊Ѝԏ؊܉࡞ॕਅଁఄ൑ฆདྷစᄛሖፋᐜᕊᙌ᜘᠑ᤒᩅᬖ᱇ᵀḕ἗⁄ⅾ≽⌫⑿╽☮✩⠯⥳⩵⭱Ⱓⴤ⹰⽲ぴㄺ㉪㍨㑩㕨㘽㝪㠼㤱㨾㬰㱥㴴㸰㼳",
                "xčɘ͞џԌ؋܋࡞इਅଂంഃ๔༃ၓᄝቈጕᐝᕈᙌᝏᡎᤒᨖᭇᰖᴐṀἒ⁅ℬ≽〈␯┭☪✭⠠⤦⩲⭰Ⱔⴢ⸧⼢〠ㄺ㉭㌺㐼㔲㘿㜽㠾㤶㩠㭡㰶㴻㹠㼱",
                "uĎɚ͜Љ՟ٜ܈ࠎऄ੔୑ఆഁ๖༃ၑᅎሙፉᐘᕈᘝ᜛᠙ᤗᩇᬜᰓᵇṀὅ—K∮⌫␫┪♼✭⠫⥱⩴⬥Ⱔ⵵⸥⼢ぴㄸ㈼㍩㑩㕨㘻㝯㠽㥥㩢㭤㱡㴱㸻㽥",
                "%Şȏ̋ЅԂ؎܎ࠋं਎ଁ఍ഋซ༇ၖᅉቈጜᑏᕎᙈᝏ᠛᥁ᨔᬝᰝᴒḕὅ‘℩∧⍹⑸┫♼✫⠠⤣⨤⬦Ⱳⴧ⸫⽷ひㄾ㈽㌴㐵㔻㙬㝫㡪㥣㨾㬽㱠㴺㸴㼱",
                "!ďɝ̅ўԊٙ܈ࠀॖ੐ୖౕഀค༅ၕᄛሖጔᐕᔓᘒ᜚᠑ᤓᩀ᭄᱅ᵅḚὂ⁅ⅾ∪⍿⑹┭♹✭⡽⥱⨤⭰ⱶⴥ⸢⼡〠ㄾ㈹㍬㐺㕯㙮㝨㠸㥦㩤㭦㰱㵧㸵㼳" };

            // Randomly choose a signing key
            Random random = new Random();

            int keyid = random.Next(0, TOKEN_SIGNING_KEYS.Length);
            var chosenKey = TOKEN_SIGNING_KEYS[keyid];

			// de-obfuscate chosen key
			chosenKey = GetString(chosenKey);

            byte[] encryptKey = new byte[chosenKey.Length / 2];
            for (int i = 0; i < chosenKey.Length; i += 2)
            {
                encryptKey[i / 2] = Convert.ToByte(chosenKey.Substring(i, 2), 16);
            }

            logger.Info("Key ID Chosen: " + keyid.ToString());

			// Get current unix time

			// Consider using an online API for this rather than trusting the system clock,
			// as being a couple minutes off will make the endpoint API calls fail
            var authIssueTimestamp = (int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
            var authExpiryTimestamp = authIssueTimestamp + expiryTime;
            var algorithm = Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256;

            // Set the JWT header and payload
            logger.Info("Setting claims...");
            var claims = new List<Claim>
            {
                new Claim("dom", domain),
                new Claim("iat", authIssueTimestamp.ToString(), ClaimValueTypes.Integer32),
                new Claim("exp", authExpiryTimestamp.ToString(), ClaimValueTypes.Integer32)
            };

            var signingKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(encryptKey);
            var signingCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(signingKey, algorithm);

            var jwtHeader = new JwtHeader(signingCredentials)
            {
                { "kid", keyid.ToString() }
            };

            var jwtPayload = new JwtPayload(claims);
            var jwtSecurityToken = new JwtSecurityToken(jwtHeader, jwtPayload);

            logger.Info("Creating token and returning...");
            return new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
        }

        // obfuscation function, you can use this both to encrypt the string and to decrypt the string
        // taken from https://social.msdn.microsoft.com/Forums/vstudio/en-US/658ab629-e603-4e6f-985c-2bb8c1669b27/great-function-for-string-obfuscation-against-decompilation?forum=csharpgeneral
        private static string GetString(string str)
        {
            int length = str.Length;
            var array = new char[length];

            for (int i = 0; i < array.Length; i++)
            {
                char c = str[i];

                var b = (byte)(c ^ length - i);
                var b2 = (byte)((c >> 8) ^ i);
                array[i] = (char)(b2 << 8 | b);
            }

            return string.Intern(new string(array));
        }

        public static async Task<string> SendDomainToken(string jwtToken, string endpoint, string apiKey)
        {
            var client = new HttpClient();
            client.DefaultRequestHeaders.Accept.ParseAdd("application/json");

            endpoint = endpoint + $"?jwt={jwtToken}";
            logger.Info("Endpoint: " + endpoint);

            // de-obfuscate the API key
            apiKey = GetString(apiKey);

			//MessageBox.Show("Sending request for domain token to endpoint: " + endpoint + "\nAPI Key: " + apiKey);

            try
            {
                using (var httpClient = new HttpClient())
                {
                    httpClient.DefaultRequestHeaders.Add("x-api-key", apiKey);

                    using (var response = await httpClient.GetAsync(endpoint))
                    {
                        if (response.IsSuccessStatusCode)
                        {
                            logger.Info("Response ok");

                            // Check the content type of the response
                            if (response.Content.Headers.ContentType.MediaType == "application/json")
                            {
                                return await response.Content.ReadAsStringAsync();
                            }
                            else
                            {
                                string responseContent = await response.Content.ReadAsStringAsync();
                                MessageBox.Show("Non-JSON response received from Domain API: " + responseContent);
                                logger.Error("Non-JSON response received from Domain API: " + responseContent);
                                return null;
                            }
                        }
                        else
                        {
                            string responseContent = await response.Content.ReadAsStringAsync();
                            MessageBox.Show(response.StatusCode.ToString() + " error received from Domain API: " + responseContent);
                            logger.Error(response.StatusCode.ToString() + " error received from Domain API: " + responseContent);
                            return null;
                        }
                    }
                }
            }
            catch (Exception e)
            {
                MessageBox.Show("Exception while requesting: " + e);
                logger.Error("Exception while requesting: " + e);
                return null;
            }
        }



        public static async Task<string> SendToken(string jwtToken, string endpoint, string authToken, string apiKey, string deviceID)
        {
            var data = new Dictionary<string, string>
            {
                {"jwt", jwtToken},
                {"aadToken", authToken}
            };

            var json = JsonConvert.SerializeObject(data);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

			//de-obfuscate the API key
			apiKey = GetString(apiKey);

			try
			{
                using (var httpClient = new HttpClient())
                {
                    httpClient.DefaultRequestHeaders.Add("x-api-key", apiKey);

                    using (var response = await httpClient.PostAsync(endpoint, content))
                    {
                        if (response.IsSuccessStatusCode)
                        {

                            return await response.Content.ReadAsStringAsync();
                        }
                        else
                        {
							string message = "";
							try
							{
                                JObject jsonObject = JsonConvert.DeserializeObject<JObject>(await response.Content.ReadAsStringAsync());
                                message = (string)jsonObject["message"];
                            }
							catch (JsonReaderException e)
							{
                                MessageBox.Show("Error received from Endpoint Provisioning API: " + await response.Content.ReadAsStringAsync());
                                logger.Error("Error received from Endpoint Provisioning API: " + await response.Content.ReadAsStringAsync());
								return null;
                            }

                            if (response.StatusCode.Equals(400))
							{
                                MessageBox.Show("Endpoint for this device does not exist on zero trust network. If device recently registered, please wait 15 minutes before trying again. Otherwise contact your system administrator and quote device ID " + deviceID);
                            }

                            MessageBox.Show("Error received from Endpoint Provisioning API: " + message);
                            logger.Error("Error received from Endpoint Provisioning API: " + await response.Content.ReadAsStringAsync());
                            return null;
						}
                    }
                }
            }
			catch (Exception e)
			{
                MessageBox.Show("Exception while requesting: " + e);
                logger.Error("Exception while requesting: " + e);
                return null;
            }
            
        }

        public static string EncodeEndpointJwtToken(string deviceID, string username, string sourceIP, string objectID, int expiryTime)
        {
			logger.Info("Encrypting key...");

            string[] TOKEN_SIGNING_KEYS = new string[8]{
                "pĆȈ̈Ѝ՟؏ݘࠊ॓ਅ\u0b0dఅ\u0d50๐ཐၑᅊቍፉᐕᔚᘛᝊ᠙᥅ᩄᬓ᱁ᴖṁὀ‐K∧⌯\u242f┫♸✮⠯⤧⨯⬠ⱱ\u2d2b⸢⽰〤ㅪ㈿㌴㑩㔳㘸㜼㠻㤾㨵㭦㰳㵥㸱㼵",
                "yďȏ̉њ՝،܍࡞ॕਁ\u0b50ఁ\u0d55๐༄ၒᄜሟጛᑈᕍᘒᜑᡍᤑ᨟ᬑᰝᵂḒἔ⁄ℭ≻⌫\u242c╽♿❽⡺⥵⨣⬦Ⱒ\u2d71⸣⽷〠ㅪ㈼㍩㑪㕨㘹㜼㠾㥤㨵㭣㰲㵠㹣㼹",
                "rřȇ̅Ќ՘ٞ܁࡝॔ਃଆ౐ഊ๑བྷဇᄛቋፉᐙᔒᘓ᜛ᡉᤔ᨟ᬕ᱇ᵅṄἘ‗K∧⍻␫╿☬✡⠨⥱⨣⬢Ɒⴧ⸫⼩ふㄻ㉪㌵㐿㕯㙩㜸㠱㤶㩥㬱㰼㵢㸷㼸",
                "sĆȍ̊Ѝԏ؊܉࡞ॕਅଁఄ൑ฆདྷစᄛሖፋᐜᕊᙌ᜘᠑ᤒᩅᬖ᱇ᵀḕ἗⁄ⅾ≽⌫⑿╽☮✩⠯⥳⩵⭱Ⱓⴤ⹰⽲ぴㄺ㉪㍨㑩㕨㘽㝪㠼㤱㨾㬰㱥㴴㸰㼳",
                "xčɘ͞џԌ؋܋࡞इਅଂంഃ๔༃ၓᄝቈጕᐝᕈᙌᝏᡎᤒᨖᭇᰖᴐṀἒ⁅ℬ≽〈␯┭☪✭⠠⤦⩲⭰Ⱔⴢ⸧⼢〠ㄺ㉭㌺㐼㔲㘿㜽㠾㤶㩠㭡㰶㴻㹠㼱",
                "uĎɚ͜Љ՟ٜ܈ࠎऄ੔୑ఆഁ๖༃ၑᅎሙፉᐘᕈᘝ᜛᠙ᤗᩇᬜᰓᵇṀὅ—K∮⌫␫┪♼✭⠫⥱⩴⬥Ⱔ⵵⸥⼢ぴㄸ㈼㍩㑩㕨㘻㝯㠽㥥㩢㭤㱡㴱㸻㽥",
                "%Şȏ̋ЅԂ؎܎ࠋं਎ଁ఍ഋซ༇ၖᅉቈጜᑏᕎᙈᝏ᠛᥁ᨔᬝᰝᴒḕὅ‘℩∧⍹⑸┫♼✫⠠⤣⨤⬦Ⱳⴧ⸫⽷ひㄾ㈽㌴㐵㔻㙬㝫㡪㥣㨾㬽㱠㴺㸴㼱",
                "!ďɝ̅ўԊٙ܈ࠀॖ੐ୖౕഀค༅ၕᄛሖጔᐕᔓᘒ᜚᠑ᤓᩀ᭄᱅ᵅḚὂ⁅ⅾ∪⍿⑹┭♹✭⡽⥱⨤⭰ⱶⴥ⸢⼡〠ㄾ㈹㍬㐺㕯㙮㝨㠸㥦㩤㭦㰱㵧㸵㼳" };

            // Randomly choose a signing key
            Random random = new Random();

			int keyid = random.Next(0, TOKEN_SIGNING_KEYS.Length);
			var chosenKey = TOKEN_SIGNING_KEYS[keyid];

            // de-obfuscate chosen key
            chosenKey = GetString(chosenKey);

			// Convert the string in to a byte array
            byte[] encryptKey = new byte[chosenKey.Length / 2];
			for (int i = 0; i < chosenKey.Length; i += 2)
            {
                encryptKey[i / 2] = Convert.ToByte(chosenKey.Substring(i, 2), 16);
            }

            logger.Info("Key ID Chosen: " + keyid.ToString());

            var authIssueTimestamp = (int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
            var authExpiryTimestamp = authIssueTimestamp + expiryTime;
            var algorithm = Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256;

			// Set the JWT header and payload
			logger.Info("Setting claims...");
            var claims = new List<Claim>
                {
                    new Claim("dev", deviceID),
                    new Claim("upn", username),
                    new Claim("ip", sourceIP),
                    new Claim("oid", objectID),
                    new Claim("iat", authIssueTimestamp.ToString(), ClaimValueTypes.Integer32),
                    new Claim("exp", authExpiryTimestamp.ToString(), ClaimValueTypes.Integer32)
                };

            var signingKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(encryptKey);
            var signingCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(signingKey, algorithm);

            var jwtHeader = new JwtHeader(signingCredentials)
            {
                { "kid", keyid.ToString() }
            };

            var jwtPayload = new JwtPayload(claims);
            var jwtSecurityToken = new JwtSecurityToken(jwtHeader, jwtPayload);

			logger.Info("Creating token and returning...");
            return new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
        }

        public static async Task<string> GetCurrentExternalIPAsync()
        {
            using (var client = new HttpClient())
            {
                var response = await client.GetAsync("https://api.ipify.org");
                if (response.IsSuccessStatusCode)
                {
                    return await response.Content.ReadAsStringAsync();
                }
                else
                {
                    logger.Error($"Failed to get external IP: {response.ReasonPhrase}");
					return null;
                }
            }
        }

        public static async Task<List<Dictionary<string, object>>> GetOwnedDevices(string accessToken)
        {
            var devicesList = new List<Dictionary<string, object>>();

            // Set up the HTTP request
            var endpoint = "https://graph.microsoft.com/v1.0/me/ownedDevices";
            var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            // Send the request and read the response as a string
            logger.Info("Sending request for user's owned devices");
            //MessageBox.Show("Sending request for user's owned devices");
            var httpClient = new HttpClient();
            var response = await httpClient.SendAsync(request);
            logger.Info("Response received: " + await response.Content.ReadAsStringAsync());
            //MessageBox.Show("Response received: " + await response.Content.ReadAsStringAsync());
            var json = await response.Content.ReadAsStringAsync();

            logger.Info("Parsing response JSON...");
            //MessageBox.Show("Parsing response JSON...");
            // Parse the JSON string into a JObject object
            var root = JsonConvert.DeserializeObject<JObject>(json);

            logger.Info("Processing list of user's devices...");
            //MessageBox.Show("Processing list of user's devices...");
            // Get list of all the user's devices
            var devicesElement = root["value"];
            if (devicesElement != null && devicesElement.Type == JTokenType.Array)
            {
                foreach (var deviceElement in devicesElement)
                {
                    var device = deviceElement.ToObject<Dictionary<string, object>>();
                    devicesList.Add(device);
                }
            }

            return devicesList;
        }

        public static async Task<string> GetUPN(string auth_token)
        {
            // Get the UPN of the user that the AAD auth belongs to
            var endpoint = "https://graph.microsoft.com/v1.0/me";
			logger.Info("Making request to graph for personal account info...");
            var graphRequest = new HttpRequestMessage(HttpMethod.Get, endpoint);
            graphRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", auth_token);

            var graphClient = new HttpClient();
            var graphResponse = await graphClient.SendAsync(graphRequest);

            graphResponse.EnsureSuccessStatusCode();
            var graphResponseBody = await graphResponse.Content.ReadAsStringAsync();

            var graphResponseJson = JsonConvert.DeserializeObject<Dictionary<string, object>>(graphResponseBody);
            var signedInUpn = graphResponseJson["userPrincipalName"].ToString();

            // Return the signed-in user's email (or user principal name)
            return signedInUpn;
        }

		public static async Task<string> GetEmailDomain()
		{
			string output = RunDsregcmd();
			if (output == null)
			{
				return null;
			}
			string x;
            try
            {
				logger.Info("Output: " + output);
				if (!output.Contains("WorkplaceThumbprint"))
				{
					if (output.Contains("TenantId"))
					{
						logger.Info("AAD joined device detected.");
						return await AADJoinedGetDomain(output);
					}
					logger.Info("No workplaceThumbprint found.");
					return null;
				}
				// Find the line that has the Workplace Thumbprint
                x = output.Substring(output.IndexOf("WorkplaceThumbprint")).Split('\n')[0].Split(':')[1].Trim();
            }
            catch (Exception ex)
            {
                logger.Error($"Error: {ex}");
				MessageBox.Show("Error while reading device details.");
				return null;
            }

            if (string.IsNullOrEmpty(x))
            {
                logger.Error("No Business/School-Account found on this Host");
                return null;
            }
            else
            {
                var accountThumbPrint = x.Substring(x.LastIndexOf(':') + 1).Trim();
                var regPath = $@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\JoinInfo\{accountThumbPrint}";
                var key = Registry.CurrentUser.OpenSubKey(regPath);
                var userMail = key.GetValue("UserEmail").ToString().Trim();
				userMail = userMail.Split('@')[1];

                logger.Info($"We found an existing Account with Thumbprint {accountThumbPrint} and Mail-Address {userMail}");
                return userMail;
            }
        } 

		async public static Task<string> AADJoinedGetDomain(string dsregOutput)
		{
            var lines = dsregOutput.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);

            // Initialize variables to store the values
            string tenantId = null;
            string thumbprint = null;
            string deviceId = null;
            logger.Info("Searching for AAD info in console response...");
            foreach (var line in lines)
            {
                if (line.Contains("TenantId :"))
                {
                    tenantId = line.Split(':')[1].Trim();
                }
                else if (line.Contains("Thumbprint :"))
                {
                    thumbprint = line.Split(':')[1].Trim();
                }
                else if (line.Contains("DeviceId :"))
                {
                    deviceId = line.Split(':')[1].Trim();
                }
            }
			logger.Info("TenantID: " + tenantId);
			logger.Info("Thumbprint: " + thumbprint);
			logger.Info("DeviceID: " + deviceId);

            var regPath = $@"SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo\{thumbprint}";
            var key = Registry.LocalMachine.OpenSubKey(regPath);
			if (key is null)
			{
				return null;
			}
            var userMail = key.GetValue("UserEmail").ToString().Trim();
            userMail = userMail.Split('@')[1];

            logger.Info($"We found an existing Account with Thumbprint {thumbprint} and Mail-Address {userMail}");
            return userMail;
		}

		public static Dictionary<string, object> AADJoinedGetWorkAccInfo(string dsregOutput)
		{
            var lines = dsregOutput.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);

            // Initialize variables to store the values
            string tenantId = null;
            string thumbprint = null;
            string deviceId = null;
            logger.Info("Searching for AAD info in console response...");
            foreach (var line in lines)
            {
                if (line.Contains("TenantId :"))
                {
                    tenantId = line.Split(':')[1].Trim();
                }
                else if (line.Contains("Thumbprint :"))
                {
                    thumbprint = line.Split(':')[1].Trim();
                }
                else if (line.Contains("DeviceId :"))
                {
                    deviceId = line.Split(':')[1].Trim();
                }
            }
            logger.Info("TenantID: " + tenantId);
            logger.Info("Thumbprint: " + thumbprint);
            logger.Info("DeviceID: " + deviceId);

            logger.Info("Account info found!");
            var workAccount = new Dictionary<string, object>
            {
                { "WorkplaceDeviceId", deviceId },
                { "WorkplaceTenantId", tenantId },
                { "WorkplaceJoined", true }
            };
            string workAccountString = string.Join(", ", workAccount.Select(kv => $"{kv.Key}: {kv.Value}"));
            logger.Info("Account info: " + workAccountString);
            return workAccount;
        }

        public static Dictionary<string, object> GetWorkAccountInfo()
        {

			string output = RunDsregcmd();
			if (output is null)
			{
				return null;
			}

            logger.Info("Captured output:\n" + output);
			logger.Info("splitting lines");

			// If a device has a tenant but isn't in a workplace, then it's AAD joined
            if (!output.Contains("WorkplaceThumbprint"))
            {
                if (output.Contains("TenantId"))
                {
                    logger.Info("AAD joined device detected.");
                    return AADJoinedGetWorkAccInfo(output);
                }
                logger.Info("No workplaceThumbprint found.");
                return null;
            }

            // Split the output into lines
            var lines = output.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);

			// Initialize variables to store the values
			string workplace_device_id = null;
			string workplace_tenant_id = null;
			bool workplace_joined = false;

			logger.Info("Searching for account info in console response...");
            // Search for the lines containing the WorkplaceDeviceId, WorkplaceTenantId, and WorkplaceJoined labels
            foreach (var line in lines)
            {
                if (line.Contains("WorkplaceDeviceId :"))
                {
                    workplace_device_id = line.Split(':')[1].Trim();
                }
                else if (line.Contains("WorkplaceTenantId :"))
                {
                    workplace_tenant_id = line.Split(':')[1].Trim();
                }
                else if (line.Contains("WorkplaceJoined :"))
                {
                    workplace_joined = line.Split(':')[1].Trim().ToUpper() == "YES";
                }
            }

            // Return the results as a dictionary
            if (!string.IsNullOrEmpty(workplace_device_id) && !string.IsNullOrEmpty(workplace_tenant_id))
            {
				logger.Info("Account info found!");
                var workAccount = new Dictionary<string, object>
                    {
                        { "WorkplaceDeviceId", workplace_device_id },
                        { "WorkplaceTenantId", workplace_tenant_id },
                        { "WorkplaceJoined", workplace_joined }
                    };
                string workAccountString = string.Join(", ", workAccount.Select(kv => $"{kv.Key}: {kv.Value}"));
                logger.Info("Account info: " + workAccountString);
                return workAccount;
            }
            else
            {
				logger.Error("No account info found.");
                return null;
            }

        }

		public static string RunDsregcmd()
		{
            // Run the command and capture the output
            logger.Info("Running dsregcmd /status");

            // Don't even ask about the SysNative here
            // Basically, if a 32 bit program in a 64 bit OS asks to run something in System32,
            // Windows will intercept that and instead point the program to the SysWOW64 directory
            // Then a FileNotFound error will happen. The SysNative is to bypass this redirection
            var executable = @"C:\Windows\SysNative\dsregcmd.exe";
            if (!File.Exists(executable))
            {
                executable = @"C:\Windows\System32\dsregcmd.exe";
                if (!File.Exists(executable))
                {
                    logger.Error("dsregcmd.exe could not be found.");
                    return null;
                }
            }
            logger.Info("File path: " + executable);
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = executable,
                    Arguments = "/status",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                }
            };
            logger.Info("starting process");
            try
            {
                process.Start();

            }
            catch (Exception ex)
            {
                logger.Error(ex);
            }
            logger.Info("reading process");
            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
			return output;
        }

        private void OnTimedEvent(object sender, EventArgs e) {
			TimeSpan span = (DateTime.Now - _startDate);
			int hours = span.Hours;
			int minutes = span.Minutes;
			int seconds = span.Seconds;
			var hoursString = (hours > 9) ? hours.ToString() : "0" + hours;
			var minutesString = (minutes > 9) ? minutes.ToString() : "0" + minutes;
			var secondsString = (seconds > 9) ? seconds.ToString() : "0" + seconds;
			ConnectedTime.Content = "Uptime: " + hoursString + ":" + minutesString + ":" + secondsString;
		}

		private void InitializeTimer(int millisAgoStarted) {
			_startDate = DateTime.Now.Subtract(new TimeSpan(0, 0, 0, 0, millisAgoStarted));
			_tunnelUptimeTimer = new System.Windows.Forms.Timer();
			_tunnelUptimeTimer.Interval = 100;
			_tunnelUptimeTimer.Tick += OnTimedEvent;
			_tunnelUptimeTimer.Enabled = true;
			_tunnelUptimeTimer.Start();
		}

		async private Task DoConnectAsync() {
			try {
				SetNotifyIcon("green");
				TunnelConnected(true);

				for (int i = 0; i < identities.Count; i++) {
					await serviceClient.IdentityOnOffAsync(identities[i].Identifier, true);
				}
				for (int i = 0; i < IdList.Children.Count; i++) {
					IdentityItem item = IdList.Children[i] as IdentityItem;
					item._identity.IsEnabled = true;
					item.RefreshUI();
				}
			} catch (ServiceException se) {
				ShowError("Error Occurred", se.Message + " " + se.AdditionalInfo);
			} catch (Exception ex) {
				ShowError("Unexpected Error", "Code 3:" + ex.Message);
			}
		}

		async private void Disconnect(object sender, RoutedEventArgs e) {
			try {
				ShowLoad("Disabling Service", "Please wait for the service to stop.");
				var r = await monitorClient.StopServiceAsync();
				if (r.Code != 0) {
					logger.Warn("ERROR: Error:{0}, Message:{1}", r.Error, r.Message);
				} else {
					logger.Info("Service stopped!");
				}
			} catch(Exception ex) {
				logger.Error(ex, "unexpected error: {0}", ex.Message);
				ShowError("Error Disabling Service", "An error occurred while trying to disable the data service. Is the monitor service running?");
			}
			HideLoad();
		}

		internal void ShowLoad(string title, string msg) {
			this.Dispatcher.Invoke(() => {
				LoadingDetails.Text = msg;
				LoadingTitle.Content = title;
				LoadProgress.IsIndeterminate = true;
				LoadingScreen.Visibility = Visibility.Visible;
				UpdateLayout();
			});
		}

		internal void HideLoad() {
			this.Dispatcher.Invoke(() => {
				LoadingScreen.Visibility = Visibility.Collapsed;
				LoadProgress.IsIndeterminate = false;
			});
		}

		private void FormFadeOut_Completed(object sender, EventArgs e) {
			closeCompleted = true;
		}
		private bool closeCompleted = false;
		private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e) {
			if (!closeCompleted) {
				FormFadeOut.Begin();
				e.Cancel = true;
			}
		}

		public void ShowError(string title, string message) {
			this.Dispatcher.Invoke(() => {
				ErrorTitle.Content = title;
				ErrorDetails.Text = message;
				ErrorView.Visibility = Visibility.Visible;
			});
		}

		private void CloseError(object sender, RoutedEventArgs e) {
			this.Dispatcher.Invoke(() => {
				ErrorView.Visibility = Visibility.Collapsed;
				NoServiceView.Visibility = Visibility.Collapsed;
				CloseErrorButton.IsEnabled = true;
			});
		}

		private void CloseApp(object sender, RoutedEventArgs e) {
			Application.Current.Shutdown();
		}

		private void MainUI_Deactivated(object sender, EventArgs e) {
			if (this._isAttached) {
#if DEBUG
				logger.Debug("debug is enabled - windows pinned");
#else
				this.Visibility = Visibility.Collapsed;
#endif
			}
		}

		private void Label_MouseDoubleClick(object sender, MouseButtonEventArgs e) {
			Placement();
		}

		int cur = 0;
		LogLevelEnum[] levels = new LogLevelEnum[] { LogLevelEnum.FATAL, LogLevelEnum.ERROR, LogLevelEnum.WARN, LogLevelEnum.INFO, LogLevelEnum.DEBUG, LogLevelEnum.TRACE, LogLevelEnum.VERBOSE };
		public LogLevelEnum NextLevel() {
			cur++;
			if (cur > 6) {
				cur = 0;
			}
			return levels[cur];
		}

		private void IdList_LayoutUpdated(object sender, EventArgs e) {
			Placement();
		}

		async private void CollectLogFileClick(object sender, RoutedEventArgs e) {
			await CollectLogFiles();
		}
		async private Task CollectLogFiles() {
			MonitorServiceStatusEvent resp = await monitorClient.CaptureLogsAsync();
			if (resp != null) {

				logger.Info("response: {0}", resp.Message);
			} else {
				ShowError("Error Collecting Feedback", "An error occurred while trying to gather feedback. Is the monitor service running?");
            }
		}

		/// <summary>
		/// Show the blurb as a growler notification
		/// </summary>
		/// <param name="message">The message to show</param>
		/// <param name="url">The url or action name to execute</param>
		public async Task ShowBlurbAsync(string message, string url, string level="error") {
			RedBlurb.Visibility = Visibility.Collapsed;
			InfoBlurb.Visibility = Visibility.Collapsed;
			if (level=="error") {
				RedBlurb.Visibility = Visibility.Visible;
			} else {
				InfoBlurb.Visibility = Visibility.Visible;
			}
			Blurb.Content = message;
			_blurbUrl = url;
			BlurbArea.Visibility = Visibility.Visible;
			BlurbArea.Opacity = 0;
			BlurbArea.Margin = new Thickness(0, 0, 0, 0);
			DoubleAnimation animation = new DoubleAnimation(1, TimeSpan.FromSeconds(.3));
			ThicknessAnimation animateThick = new ThicknessAnimation(new Thickness(15, 0, 15, 15), TimeSpan.FromSeconds(.3));
			BlurbArea.BeginAnimation(Grid.OpacityProperty, animation);
			BlurbArea.BeginAnimation(Grid.MarginProperty, animateThick);
			await Task.Delay(5000);
			HideBlurb();
		}

		/// <summary>
		/// Execute the hide operation wihout an action from the growler
		/// </summary>
		/// <param name="sender">The object that was clicked</param>
		/// <param name="e">The click event</param>
		private void DoHideBlurb(object sender, MouseButtonEventArgs e) {
			HideBlurb();
		}

		/// <summary>
		/// Hide the blurb area
		/// </summary>
		private void HideBlurb() {
			DoubleAnimation animation = new DoubleAnimation(0, TimeSpan.FromSeconds(.3));
			ThicknessAnimation animateThick = new ThicknessAnimation(new Thickness(0, 0, 0, 0), TimeSpan.FromSeconds(.3));
			animation.Completed += HideComplete;
			BlurbArea.BeginAnimation(Grid.OpacityProperty, animation);
			BlurbArea.BeginAnimation(Grid.MarginProperty, animateThick);
		}

		/// <summary>
		/// Hide the blurb area after the animation fades out
		/// </summary>
		/// <param name="sender">The animation object</param>
		/// <param name="e">The completion event</param>
		private void HideComplete(object sender, EventArgs e) {
			BlurbArea.Visibility = Visibility.Collapsed;
		}

		/// <summary>
		/// Execute a predefined action or url when the pop up is clicked
		/// </summary>
		/// <param name="sender">The object that was clicked</param>
		/// <param name="e">The click event</param>
		private void BlurbAction(object sender, MouseButtonEventArgs e) {
			if (_blurbUrl.Length>0) {
				// So this simply execute a url but you could do like if (_blurbUrl=="DoSomethingNifty") CallNifyFunction();
				if (_blurbUrl== this.RECOVER) {
					this.ShowMFA(IdentityMenu.Identity, 4);
				} else {
					Process.Start(new ProcessStartInfo(_blurbUrl) { UseShellExecute = true });
				}
				HideBlurb();
			} else {
				HideBlurb();
			}
		}

		private void ShowAuthenticate(ZitiIdentity identity) {
			MFAAuthenticate(identity);
		}

		private void ShowRecovery(ZitiIdentity identity) {
			ShowMFARecoveryCodes(identity);
		}





		private ICommand someCommand;
		public ICommand SomeCommand {
			get {
				return someCommand
					?? (someCommand = new ActionCommand(() => {
						if (DebugForm.Visibility == Visibility.Hidden) {
							DebugForm.Visibility = Visibility.Visible;
						} else {
							DebugForm.Visibility = Visibility.Hidden;
						} 
					}));
			}
            set {
				someCommand = value;
            }
		}

		private void DoLoading(bool isComplete) {
			if (isComplete) HideLoad();
			else ShowLoad("Loading", "Please Wait.");
		}

        public static implicit operator MainWindow(MainMenu v)
        {
            throw new NotImplementedException();
        }
    }

	public class ActionCommand : ICommand {
		private readonly Action _action;

		public ActionCommand(Action action) {
			_action = action;
		}

		public void Execute(object parameter) {
			_action();
		}

		public bool CanExecute(object parameter) {
			return true;
		}
#pragma warning disable CS0067 //The event 'ActionCommand.CanExecuteChanged' is never used
		public event EventHandler CanExecuteChanged;
#pragma warning restore CS0067 //The event 'ActionCommand.CanExecuteChanged' is never used
	}

    public class RegistrationStatus
    {
        public string Registered { get; set; }
    }
}
