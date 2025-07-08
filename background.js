chrome.runtime.onInstalled.addListener(() => {
    console.log("Phishing URL Detection Extension installed.");
});

// Function to check URL status in different lists
async function checkURLStatus(url) {
    try {
        console.log('Checking URL status for:', url); // Debug log

        // Check blacklist
        const blacklistResponse = await fetch('http://127.0.0.1:5000/admin/blacklist', {
            headers: {
                'X-Admin-Key': 'your-secure-admin-key'  // Add admin key
            }
        });
        if (blacklistResponse.ok) {
            const blacklist = await blacklistResponse.json();
            console.log('Blacklist:', blacklist); // Debug log
            if (blacklist.some(entry => entry.url === url)) {
                console.log('URL found in blacklist'); // Debug log
                return { status: "Unsafe", color: "red", message: "Website is blacklisted" };
            }
        }

        // Check whitelist (bookmarks)
        const whitelistResponse = await fetch('http://127.0.0.1:5000/whitelist');
        if (whitelistResponse.ok) {
            const whitelist = await whitelistResponse.json();
            console.log('Whitelist:', whitelist); // Debug log
            if (whitelist.some(entry => entry.url === url)) {
                console.log('URL found in whitelist'); // Debug log
                return { status: "Safe", color: "green", message: "Website is whitelisted" };
            }
        }

        // Check pending reports
        const pendingResponse = await fetch('http://127.0.0.1:5000/admin/pending', {
            headers: {
                'X-Admin-Key': 'your-secure-admin-key'  // Add admin key
            }
        });
        if (pendingResponse.ok) {
            const pending = await pendingResponse.json();
            console.log('Pending list:', pending); // Debug log
            if (pending.some(entry => entry.url === url)) {
                console.log('URL found in pending list'); // Debug log
                return { status: "Pending", color: "orange", message: "Website is under review" };
            }
        }

        console.log('URL not found in any list'); // Debug log
        return { status: "Unknown", color: "blue", message: "Welcome to PhiShield" };
    } catch (error) {
        console.error('Error checking URL status:', error);
        return { status: "Unknown", color: "blue", message: "Welcome to PhiShield" };
    }
}

// Listen for tab updates
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    // Only proceed if the tab is complete and has a URL
    if (changeInfo.status === 'complete' && tab.url) {
        console.log('Tab updated:', tab.url); // Debug log
        const status = await checkURLStatus(tab.url);
        console.log('URL status:', status); // Debug log
        
        // Update the extension icon badge
        chrome.action.setBadgeText({ 
            text: status.status === "Unknown" ? "" : status.status.charAt(0),
            tabId: tabId 
        });
        chrome.action.setBadgeBackgroundColor({ 
            color: status.color,
            tabId: tabId 
        });

        // Also update the popup if it's open
        try {
            const views = chrome.extension.getViews({ type: "popup" });
            if (views.length > 0) {
                views.forEach(view => {
                    if (view.location.href.includes('popup.html')) {
                        view.postMessage({ 
                            type: 'updateStatus',
                            status: status
                        }, '*');
                    }
                });
            }
        } catch (error) {
            console.error('Error updating popup:', error);
        }
    }
});

// Listen for messages from the popup script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "checkUrl") {
        const url = request.url;

        // Send the URL to the Flask backend for phishing detection
        fetch("http://127.0.0.1:5000/", {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
            },
            body: new URLSearchParams({ url: url }),
        })
            .then((response) => response.json())
            .then((data) => {
                if (data.xx >= 0.5) {
                    sendResponse({
                        result: { isSafe: true, confidence: (data.xx * 100).toFixed(2) },
                    });
                } else {
                    sendResponse({
                        result: { isSafe: false, confidence: ((1 - data.xx) * 100).toFixed(2) },
                    });
                }
            })
            .catch((error) => {
                console.error("Error communicating with the backend:", error);
                sendResponse({ error: "Failed to check the URL." });
            });

        // Return true to indicate that the response will be sent asynchronously
        return true;
    } else if (request.action === "getUrlStatus") {
        // Handle request for URL status from popup
        checkURLStatus(request.url).then(status => {
            sendResponse(status);
        });
        return true;
    }
});

