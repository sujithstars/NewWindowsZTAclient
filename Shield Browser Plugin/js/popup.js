document.addEventListener("DOMContentLoaded", () => {

	// Grabbing the form elements in advance.
	const enabledBlock = document.getElementById("enabled");
	const disabledBlock = document.getElementById("disabled");
	const enableButton = document.getElementById("enableButton");
	const disableButton = document.getElementById("disableButton");
	const dashboardButton = document.getElementById("dashboardButton");
	const ipAddress = document.getElementById("ipAddress");
	const currentStatus = document.getElementById("currentStatus");
	const build = document.getElementById("build");
	var enabled = false;

	build.innerHTML = "Build 1.22.0";

	// Read in the IP address of the Shield Proxy, default to localhost if none is provided.
	chrome.storage.sync.get({ip:"127.0.0.1"}, function(obj) {	
		ip = obj.ip;
		if (ip == null) { ip = "127.0.0.1"; }
		ipAddress.value = ip;
	});

	// Find out if it is currently enabled from the shared storage; default is no.
	chrome.storage.sync.get({enabled:false}, function(obj) {	
		enabled = obj.enabled;
		// Now that we know, set the buttons to either say "enabled" or to connect to
		// the dashboard.
		enableButtons();
	});

	// Find out if it is currently connected from the shared storage; default is no.
	chrome.storage.sync.get({connected:false}, function(obj) {	
		connected = obj.connected;
		displayStatus();
	});

	// Listen in case the connection is disabled
	function monitorChanges(changes, namespace) {
		if (changes.enabled) {
			enabled = changes.enabled.newValue;
			enableButtons();
		}
		if (changes.connected) {
			connected = changes.connected.newValue;
			displayStatus();
		}
	}
	chrome.storage.sync.onChanged.addListener(monitorChanges);

	// -------------------------------------------------------------------------------------------------------
	// enableButton listener
	//
	// Tries to connect to the ShieldProxy

	enableButton.addEventListener("click", () => {
		// I want an easy method to reset to localhost even if the user doesn't know
		// much about IP addresses. This resets it to 127.0.0.1 (the default) if they
		// blank the box. Presumably they will be given instructions if they need to
		// set it to anything else, in which case there will be a value to set it to
		// instead.
		if (ipAddress.value == "") {
			chrome.storage.sync.set({ ip: "127.0.0.1" }, () => {
				console.log("Set IP to 127.0.0.1");
				ip = "127.0.0.1";
			});
		} else {
			chrome.storage.sync.set({ ip: ipAddress.value }, () => {
				ip = ipAddress.value;
				console.log("Set IP to " + ip);
			});
		}
		// Cool. Send a request to reconnect.
	  	chrome.runtime.sendMessage({ action: "reconnect", newValue: "true" });
	});

	// -------------------------------------------------------------------------------------------------------
	// dashboardButton listener
	//
	// Opens the dashboard on the ShieldProxy in a new tab

	dashboardButton.addEventListener("click", () => {
		// The IP address is set when they hit enable, and the dashboard 
		// is only available after enabling, so no need to confirm the IP
		// value.
		const url = "http://" + ip + ":8001/";
		chrome.tabs.create({ url });
	});

	// -------------------------------------------------------------------------------------------------------
	// disableButton listener
	//
	// Disables the connection if pressed.

	disableButton.addEventListener("click", () => {
		// Send a request to disconnect.
	  	chrome.runtime.sendMessage({ action: "disconnect", newValue: "true" });
	});

	// -------------------------------------------------------------------------------------------------------
	// enableButtons
	//
	// Displays or hides buttons based on the enabled state

	function enableButtons() {
		if (enabled) {
			enabledBlock.style.display  = "block";
			disabledBlock.style.display = "none";
		}
		else {
			enabledBlock.style.display  = "none";
			disabledBlock.style.display = "block";
		}
	}

	// -------------------------------------------------------------------------------------------------------
	// displayStatus
	//
	// Displays if it is connected or not

	function displayStatus() {
		if (connected) {
			currentStatus.innerHTML = "Intrusion Shield: Available";
		}
		else {
			currentStatus.innerHTML = "Intrusion Shield: Lost Connection";
		}
	}
});

