// -------------------------------------------------------------------------------------------------------
// Global variables

var currentId = 1002;		// ID for the declarativeNetRequest rules. Each needs a unique integer ID.
var checkedDomains = {};	// Domains that have been checked since launch and the time they were checked.
var enabled = false;		// Let's assume that enabled means that it is able to run
var connected = false;		// Let's assume that connected means that it is running
var ip = "127.0.0.1";		// Default IP for the shield
var lastStatusCheck = 0;		
var lastUpdateCheck = 0;
var currentStatusFailedCount = 0;

// Based on the above, the logic is that when you click on connect, it is enabled and tries to make a 
// connection. If it loses that connection it remains enabled, but it si disconnected. If it is disabled
// it effectively loses the connection as well.

// Section 1: Things to do by default

// a) Until we check, assume that it is not connected.

chrome.storage.sync.set({ connected: false }, () => {
	console.log("Set connected to false prior to check");
	connected = false;
});

/*
chrome.storage.sync.get({enabled: false}, function(obj) {	
	enabled = obj.enabled;
});
*/

// b) Find out if we are enabled
chrome.storage.sync.get({enabled: false}, function(obj) {	
	enabled = obj.enabled;
});

// -------------------------------------------------------------------------------------------------------
// onInstalled
//
// Runs on installation. 

chrome.runtime.onInstalled.addListener(function() {
	activate();
});


// -------------------------------------------------------------------------------------------------------
// activate
//
// Initialises a connection

function activate() {
	// Generally we will connect to localhost. This tries to grab the IP from the stored data, and if the
	// data is null uses localhost.
	chrome.storage.sync.get({ip:"127.0.0.1"}, function(obj) {	
		ip = obj.ip;
		if (ip == null) { ip = "127.0.0.1"; }
	});

	// Try and activate a connection on the shield. This will turn it on if it isn't already, and let's 
	// us know its status.
	if (enabled == true) {
		fetch("http://" + ip + ":8001/activate")
			.then(response => response.json())
			.then(data => {
				if (data["status"] == "active") {
					showNotification("Intrusion Shield", "Shield is available.");
					enabled = true;
					connected = true;
					chrome.storage.sync.set({ enabled: true }, () => {
						console.log("Set enabled to true - shield active.");
					});
					chrome.storage.sync.set({ connected: true }, () => {
						console.log("Set connected to true - connection established.");
					});
					// Rather than store a block list in the plugin and in the Shield DNS, it makes more sense to store
					// it in the Shield DNS and download it when we start the Plugin. Thus step 2 is to download and add 
					// all the old blocks to the rule list
					getBlocks();
				}
			})
			.catch(error => {
				console.log("Unable to open connection to Shield Proxy.");
				showNotification("Intrusion Shield", "Unable to connect to " + "http://" + ip + ":8001/shield?activate");				
				connected = false;
				chrome.storage.sync.set({ connected: false }, () => {
					console.log("Connection to Shield Proxy lost.");
				});
			});
	}
}

// -------------------------------------------------------------------------------------------------------
// checkStatus
//
// Checks to see if a connection is available

function checkStatus() {
	if (enabled == true) {
		if (Date.now() > lastStatusCheck + 10000) {
			lastStatusCheck = Date.now();

			//setTimeout(() => controller.abort(), 3000); // sets timeout to 3 seconds

			fetch("http://" + ip + ":8001/status")
				.then(response => response.json())
				.then(data => {
					currentStatusFailedCount = 0;
					if (data["status"] == "inactive") {
						console.log("Shield inactive.");	
						showNotification("Intrusion Shield", "Intrusion Shield has been disabled.");				
						connected = false;
						chrome.storage.sync.set({ connected: false }, () => {
							console.log("Connection to Shield Proxy lost.");
						});
					} else {
						currentStatusFailedCount = 0;
						if(connected == false) {
							console.log("Shield connected.");	
							showNotification("Intrusion Shield", "Restored connection to Intrusion Shield");			
							connected = true;
							chrome.storage.sync.set({ connected: true }, () => {
								console.log("Connection to Shield Proxy restored.");
							});
						}
					}
				})
				.catch(error => {
					console.log("Failed status query.");
					currentStatusFailedCount += 1;
					if (currentStatusFailedCount > 4) {		
						if (connected) {
							showNotification("Intrusion Shield", "Lost connection to Intrusion Shield");			
							connected = false;
							chrome.storage.sync.set({ connected: false }, () => {
								console.log("Connection to Shield Proxy lost.");
							});
						}
					}
				});
		}
	}
}

// -------------------------------------------------------------------------------------------------------
// onBeforeRequest
//
// onBeforeRequest is triggered as soon as a URL is entered but before it is requested from the server.
// This is the earliest trigger we can use, but sadly it is the same trigger used by Chrome to check 
// against the declarativeNetRequest list. Thus we can detect that a page has been requested, and
// we can add it to the declarativeNetRequest, but it is too late to make the redirect occur on this path.
//
// Still, that's what is being done here - we grab the request, check it against the blocklist (via the 
// DNS Proxy), and then add it to declarativeNetRequest as a redirect if it is blocked. The DNS Proxy
// handles whitelists and everything else, so we do not need to care here.

chrome.webRequest.onBeforeRequest.addListener(
	function(details) {
		var blocked = false;

		// If the tabID has a value, we know that this is a domain that they are trying to go to.
		// It is important as we don't want to trap all traffic at this level, just the top level traffic.
		if (enabled && details.frameId === 0 && details.parentFrameId === -1) {
	  	//if (enabled && details.tabId !== -1) {

			// Grab the domain from the URL. I guess I could write something to parse it myself, but
			// as URL has a parser I might as well use that.
			var domain = (new URL(details.url)).hostname;

			// Check to see if a) it is a domain that has never been checked before, or b) it has been 
			// checked before, but not for the last 2 seconds. That 2 seconds was mostly to limit the
			// number of notifications I was getting, but really it could be longer. I do think
			// that a time limit would be wise, though, in case a domain becomes blocked or unblocked.
			if (!checkedDomains.hasOwnProperty(domain) || Date.now() > checkedDomains[domain] + 2000) {
				console.log("Cat intercepted: " + domain);
			
				// Ok, so we haven't encountered it before. Therefore we add it to the list of checked domains.
				checkedDomains[domain] = Date.now();

				// Check if the URL should be redirected
				blocked = checkURL(details);
			}

			// Normally almost nothing will be returned here. I debated including it in the response above,
			// but it seems to me that it is only a local request, so uses no bandwidth, and normally 
			// the response will contain almost no data, so the slight performance loss by doing it regularly
			// is countered by the smoothness of the user experience.
			// Oh - I forgot to say why it is happening. I'm checking to see if a user has whitelisted a
			// domain or moved a domain back to the blocklist on the Shield DNS.
			getUpdates();

			if (blocked) {
				return {cancel: true};
			}
			else {
	  			return true;
			}
		}
	},
	// Filters
	{
	  urls: [
		"<all_urls>"
	  ]
	}
);


// -------------------------------------------------------------------------------------------------------
// checkUrl(details)
//
// Sends the domain to the DNSProxy and receives a response about whether or not it is blocked.
// Also gets data about changes to the whitelist or blacklist.

function checkURL(details) {
	// Grab the domain. Rather than writing my own parser, it is much easier to rely on
	// the URL object to do work.
	let domain = (new URL(details.url)).hostname;

	// If it isn't already blocked
	if (checkForDomain(details.url) < 0) {
		// Fetch is asynchronous. In the past we had to make this synchronous, but as we are blocking the
		// URL anyway, this is just to tell the plugin that it was blocked. So it can happen any time,
		// and this improves performance.
		console.log('Querying http://' + ip + ':8001/shield?query=' + domain);

		const controller = new AbortController();
		const signal = controller.signal;

		setTimeout(() => controller.abort(), 6000); // sets timeout to 6 seconds


		fetch('http://' + ip + ':8001/shield?query=' + domain)
			.then(response => response.json())
			.then(data => {
				currentStatusFailedCount = 0;
				if (connected == false) {
					showNotification("Intrusion Shield", "Shield is available.");
					connected = true;
					chrome.storage.sync.set({ connected: true }, () => {
						console.log("Set connected to true - connection established.");
					});
				}
				// If the domain is blocked it will be noted in the response. Thus we just have to add
				// it to the blocklist.
				if (data["result"] == "blocked") {
					addToBlockList(details.url);
					if (data["previous"] == "false") {
						// Let the user know that it has been blocked.
						showNotification("Intrusion Shield", domain + " blocked by Intrusion Shield");
					}
					return true;
				}
			})
			.catch(error => {
				//showNotification("Intrusion Shield", "Lost connection to Intrusion Shield");			
				checkStatus();
				/*
				enabled = false;
				chrome.storage.sync.set({ enabled: false }, () => {
					  console.log("Connection to Shield Proxy lost.");
				});
				*/
			});
	}
	return false;
}

// -------------------------------------------------------------------------------------------------------
// addToBlockList(details)
//
// This is called if the domain has been blocked. It adds the domain to declarativeNetRequest and sets up
// the redirect.

function addToBlockList(url) {
	const domain = (new URL(url)).hostname;
	// I'd like to use a regex, because it makes this more universal.
	const regexDomain = domain.replace(/\./g, "\\.");

	// Need a unique ID, so this moves it on by one.
	currentId++;

	// Update the rule set to redirect the URL
	chrome.declarativeNetRequest.updateDynamicRules({
		// Safety check - if by some chance the ID exists, kill it.
		removeRuleIds: [currentId], 
		addRules: [
		  {
			id: currentId, 
			priority: 1,
			action: {
			  	type: "redirect",
				// Redirecting to the DNS Proxy.
			  	redirect: { "regexSubstitution": "http://" + ip + ":8001/shield?blocked=" + domain + "&url=\\0" }
			},
			condition: {
				// Per above, using a regex to make this more universal.
				regexFilter: "^https?://" + regexDomain + "/.*",
			  	resourceTypes: ["main_frame", "sub_frame"]
			}
		  }
		]
	});
}

// -------------------------------------------------------------------------------------------------------
// checkForDomain(url)
//
// Find out whether or not the domain is in the declarativeNetRequest list, and return the ID if it is.
// return -1 if it is not.
//
// Not currently used. It will need more refinement if it is applied.

function checkForDomain(url) {
	var ruleID = -1;

	chrome.declarativeNetRequest.getDynamicRules(function(rules) {
		//showNotification("Domain Check", "Rule count: " + rules.length);
		for (const rule of rules) {
			if (!rule.condition) {
				continue; // skip rules with no conditions
			}

			const condition = rule.condition;
			try {
				const regex = condition.regexFilter;
				if (regex != undefined) {
					if (url.match(regex)) {
						ruleID = rule.id;
					}
				}
			}
			catch {}
		}
	  });

	return ruleID;
}

// -------------------------------------------------------------------------------------------------------
// getUpdates()
// 
// This checks to see if there have been any changes to the whitelist (additions or removals) since the 
// last check. It won't end up doing much 99.9% of the time, as this will be a common check but will 
// rarely get a positive result.
// 
// Originally I tried to be clever and just had it send additions and removals to the blacklist. But 
// to make that work, we need to loop through the blacklist to find each removal in order to pull out
// the ID. It could work, but it is easier - and only slightly more processor intensive - just to wipe
// the blacklist and replace it with a new one.
//
// I may revisit this in the future, though, as it does feel inelegant.

function getUpdates() {

	if (Date.now() > lastUpdateCheck + 30000) {
		lastUpdateCheck = Date.now();

		const controller = new AbortController();
		const signal = controller.signal;

		setTimeout(() => controller.abort(), 3000); // sets timeout to 3 seconds

		console.log('Querying http://' + ip + ':8001/shield?updates');
		fetch('http://' + ip + ':8001/shield?updates')
			.then(response => response.json())
			.then(data => {
				// Have there been any changes?
				if (data["update"] == "true") {
					// Yes. So the response will include the full blacklist. This means we can clear
					// the blacklist ...
					disableDynamicRules();
					// ... and repopulate. Inelegant, but functional. 
					data["blocks"].forEach(function(domain) {
						addToBlockList("http://" + domain + "/");
					});
				}
			})
			.catch(error => {
				checkStatus();
			});
	}
}

// -------------------------------------------------------------------------------------------------------
// getBlocks()
//
// Downloads all of the blocks and writes them to the redirect list. Note that this will double up on
// blocks unless the rules are first cleared with clearRules(), so I have added a call to clearRules for
// safety.

function getBlocks() {
	// Per above, clear the rules first.
	disableDynamicRules();

	const controller = new AbortController();
	const signal = controller.signal;

	setTimeout(() => controller.abort(), 3000); // sets timeout to 3 seconds

	console.log('Querying http://' + ip + ':8001/shield?blocks');
	// Then we can fetch the list of blocks and ...
	fetch('http://' + ip + ':8001/shield?blocks')
		.then(response => response.json())
		.then(data => {
			// ... add them to the redirect rules.
			data["blocks"].forEach(function(domain) {
				addToBlockList("http://" + domain + "/");
			});
		})
		.catch(error => {
			checkStatus();
			/*
			showNotification("Intrusion Shield", "Lost connection to Intrusion Shield");				
			enabled = false;
			chrome.storage.sync.set({ enabled: false }, () => {
				  console.log("Connection to Shield Proxy lost.");
			});
			*/
		});
}

// -------------------------------------------------------------------------------------------------------
// clearRules()
//
// Deletes the current dynamic rule set. Mostly used to clear the board so that they can be rewritten,
// but removing the URLs is also how you activate/deactive the redirects as a whole.

function clearRules() {
	var ruleIds = [];

	// I wanted to use a filter, but this works - just loop through the rules and add their IDs
	// to an array. Then ...
	chrome.declarativeNetRequest.getDynamicRules(function(rules) {
		for (const rule of rules) {
			ruleIds.push(rule.id);
		}
	});
	
	// ... remove all the rules that are in that array. It would be nice if there was a simple
	// "clear" or "removeAll" function, but I wasn't able to find one.
	chrome.declarativeNetRequest.updateDynamicRules({
		removeRuleIds: ruleIds,
		addRules: []
	}, function() {
		console.log('All rules have been removed');
	});
}


// -------------------------------------------------------------------------------------------------------
// monitorChanges(changes, namespace)
//
// Monitor changes in data, and setup everything again. This could probably be optimized to not do
// everything on every change but why not? It causes no significant load issues.

function monitorChanges(changes, namespace) {
	if (changes.enabled) {
		enabled = changes.enabled.newValue;
		if (enabled) {
			showNotification("Intrusion Shield", "Shield enabled");
			getBlocks();
		}
		else {
			showNotification("Intrusion Shield", "Shield disabled");
			//disableDynamicRules();
		}
	}
}
chrome.storage.sync.onChanged.addListener(monitorChanges);


chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
	if (message.action === "reconnect") {
		enabled = true;
		activate();
	}
	if (message.action === "disconnect") {
		enabled = false;
		chrome.storage.sync.set({ enabled: false }, () => {
			console.log("Set enabled to false - connection disabled by user.");
		});
	}
});

async function disableDynamicRules() {
	try {
	  const dynamicRules = await getDynamicRules();
	  const ruleIdsToRemove = dynamicRules.map((rule) => rule.id);
	  await updateDynamicRules([], ruleIdsToRemove);
	  console.log("Dynamic rules disabled.");
	} catch (error) {
	  console.error("Error disabling dynamic rules:", error);
	}
  }
  
  function getDynamicRules() {
	return new Promise((resolve, reject) => {
	  chrome.declarativeNetRequest.getDynamicRules((rules) => {
		if (chrome.runtime.lastError) {
		  reject(chrome.runtime.lastError);
		} else {
		  resolve(rules);
		}
	  });
	});
  }
  
  function updateDynamicRules(addRules, removeRuleIds) {
	return new Promise((resolve, reject) => {
	  chrome.declarativeNetRequest.updateDynamicRules({ addRules, removeRuleIds }, () => {
		if (chrome.runtime.lastError) {
		  reject(chrome.runtime.lastError);
		} else {
		  resolve();
		}
	  });
	});
  }

// -------------------------------------------------------------------------------------------------------
// showNotification(title, content)
//
// Displays a message to the user.

function showNotification(title, content) {
	chrome.notifications.create(
		title,
		{
			type: "basic",
			title: title,
			iconUrl: "32.png",
			message: content
		}
	);
	chrome.notifications.clear(title);
}
  
