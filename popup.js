document.addEventListener('DOMContentLoaded', function () {
    const checkUrlButton = document.getElementById('checkUrlButton');
    const bookmarkButton = document.getElementById('bookmarkButton');
    const reportButton = document.getElementById('reportButton');
    const resultDiv = document.getElementById('prediction');
    const statusBanner = document.getElementById('statusBanner');
    const urlInput = document.getElementById('url');
    const urlForm = document.getElementById('urlForm');

    // Listen for status updates from background script
    window.addEventListener('message', function(event) {
        if (event.data && event.data.type === 'updateStatus') {
            const status = event.data.status;
            console.log('Received status update:', status); // Debug log
            updateStatusBanner(status);
        }
    });

    // Function to update status banner
    function updateStatusBanner(status) {
        statusBanner.style.backgroundColor = status.color;
        statusBanner.innerHTML = status.status;
        resultDiv.innerHTML = status.message;
        
        // Update button state
        if (status.status === "Unknown") {
            checkUrlButton.disabled = false;
            checkUrlButton.title = "Check URL";
        } else {
            checkUrlButton.disabled = true;
            checkUrlButton.title = "URL is already in list";
        }
    }

    // Get the current tab URL and check its status immediately
    chrome.tabs.query({active: true, currentWindow: true}, async function(tabs) {
        const currentURL = tabs[0].url;
        urlInput.value = currentURL;
        
        // Get status from background script
        chrome.runtime.sendMessage(
            { action: "getUrlStatus", url: currentURL },
            function(response) {
                if (response) {
                    console.log('Initial status:', response); // Debug log
                    updateStatusBanner(response);
                }
            }
        );
    });

    // Event listener for checking the URL (only for unknown URLs)
    checkUrlButton.addEventListener('click', async function () {
        try {
            // Get the current tab URL
            const tabs = await chrome.tabs.query({active: true, currentWindow: true});
            const currentURL = tabs[0].url;
            urlInput.value = currentURL;
            
            // First check if URL is in any list
            const status = await new Promise(resolve => {
                chrome.runtime.sendMessage(
                    { action: "getUrlStatus", url: currentURL },
                    response => resolve(response)
                );
            });

            // If URL is already in a list, don't proceed with check
            if (status.status !== "Unknown") {
                statusBanner.style.backgroundColor = status.color;
                statusBanner.innerHTML = status.status;
                resultDiv.innerHTML = status.message;
                return;
            }
            
            // Only proceed with phishing check if URL is not in any list
            const formData = new FormData(urlForm);
            const response = await fetch('http://127.0.0.1:5000/', {
                method: 'POST',
                body: formData,
                headers: {
                    'Accept': 'application/json'
                }
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            
            // Update the UI with the response
            if (data.xx >= 0.50) {
                resultDiv.innerHTML = `Website is ${(data.xx * 100).toFixed(2)}% safe to use`;
                statusBanner.style.backgroundColor = "green";
                statusBanner.innerHTML = "Safe";
            } else if (data.xx >= 0) {
                resultDiv.innerHTML = `Website is ${((1 - data.xx) * 100).toFixed(2)}% unsafe to use`;
                statusBanner.style.backgroundColor = "red";
                statusBanner.innerHTML = "Unsafe";
            } else {
                resultDiv.innerHTML = "Undefined URL";
                statusBanner.style.backgroundColor = "grey";
                statusBanner.innerHTML = "Unknown";
            }
        } catch (error) {
            console.error('Error:', error);
            resultDiv.innerHTML = "Error checking URL";
            statusBanner.style.backgroundColor = "orange";
            statusBanner.innerHTML = "Error";
        }
    });

    // Add bookmark button click handler
    bookmarkButton.addEventListener("click", async () => {
        const url = urlInput.value.trim();
        console.log('Attempting to bookmark URL:', url); // Debug log

        if (!url) {
            alert("Please enter a URL first");
            return;
        }

        // First check if URL is in blacklist or pending list
        try {
            // Check blacklist
            console.log('Checking blacklist...'); // Debug log
            const blacklistResponse = await fetch('http://127.0.0.1:5000/admin/blacklist', {
                headers: {
                    'X-Admin-Key': 'your-secure-admin-key'
                }
            });
            console.log('Blacklist response status:', blacklistResponse.status); // Debug log
            if (blacklistResponse.ok) {
                const blacklist = await blacklistResponse.json();
                console.log('Blacklist contents:', blacklist); // Debug log
                if (blacklist.some(entry => entry.url === url)) {
                    console.log('URL found in blacklist, preventing bookmark'); // Debug log
                    alert("Cannot bookmark: This URL is blacklisted!");
                    return;
                }
            }

            // Check pending list
            console.log('Checking pending list...'); // Debug log
            const pendingResponse = await fetch('http://127.0.0.1:5000/admin/pending', {
                headers: {
                    'X-Admin-Key': 'your-secure-admin-key'
                }
            });
            console.log('Pending response status:', pendingResponse.status); // Debug log
            if (pendingResponse.ok) {
                const pending = await pendingResponse.json();
                console.log('Pending list contents:', pending); // Debug log
                if (pending.some(entry => entry.url === url)) {
                    console.log('URL found in pending list, preventing bookmark'); // Debug log
                    alert("Cannot bookmark: This URL is under review!");
                    return;
                }
            }

            // If URL is not in blacklist or pending, proceed with bookmarking
            console.log('Proceeding with bookmark request...'); // Debug log
            const response = await fetch("http://127.0.0.1:5000/whitelist", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                },
                body: JSON.stringify({ url: url })
            });
            console.log('Bookmark response status:', response.status); // Debug log

            if (response.ok) {
                const data = await response.json();
                console.log('Bookmark response data:', data); // Debug log
                if (data.success || (data.message && data.message.includes("whitelisted successfully"))) {
                    alert(data.message || "Website bookmarked successfully!");
                    // Update status banner to show it's bookmarked
                    statusBanner.style.backgroundColor = "green";
                    statusBanner.textContent = "Safe";
                    resultDiv.textContent = "Website is bookmarked";
                    // Disable the check URL button since we know the status
                    checkUrlButton.disabled = true;
                } else {
                    console.log('Bookmark failed:', data.message); // Debug log
                    alert(data.message || "Failed to bookmark website");
                }
            } else {
                console.log('Bookmark request failed with status:', response.status); // Debug log
                const errorData = await response.json().catch(() => null);
                console.log('Error data:', errorData); // Debug log
                if (errorData?.message && errorData.message.includes("whitelisted successfully")) {
                    alert(errorData.message);
                    // Update status banner to show it's bookmarked
                    statusBanner.style.backgroundColor = "green";
                    statusBanner.textContent = "Safe";
                    resultDiv.textContent = "Website is bookmarked";
                    // Disable the check URL button since we know the status
                    checkUrlButton.disabled = true;
                } else {
                    alert("Failed to bookmark website: " + (errorData?.message || "Server error"));
                }
            }
        } catch (error) {
            console.error("Error bookmarking website:", error);
            alert("Failed to bookmark website: " + error.message);
        }
    });

    // Event listener for reporting the site
    reportButton.addEventListener('click', async function () {
        try {
            const tabs = await chrome.tabs.query({active: true, currentWindow: true});
            const currentURL = tabs[0].url;
            
            // First check if URL is already in blacklist or pending list
            const status = await new Promise(resolve => {
                chrome.runtime.sendMessage(
                    { action: "getUrlStatus", url: currentURL },
                    response => resolve(response)
                );
            });

            // If URL is already in blacklist or pending, show appropriate message
            if (status.status === "Unsafe") {
                alert("This URL is already blacklisted!");
                return;
            }
            if (status.status === "Pending") {
                alert("This URL is already under review!");
                return;
            }
            if (status.status === "Safe") {
                alert("This URL is already bookmarked!");
                return;
            }

            // Only proceed with reporting if URL is not in any list
            const response = await fetch('http://127.0.0.1:5000/report', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({ url: currentURL })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                alert(data.message || "URL reported successfully!");
                // Update status banner to show pending status
                statusBanner.style.backgroundColor = "orange";
                statusBanner.textContent = "Pending";
                resultDiv.textContent = "Website is under review";
                // Disable the check URL button since we know the status
                checkUrlButton.disabled = true;
            } else {
                throw new Error(data.error || "Failed to report URL");
            }
        } catch (error) {
            console.error('Error reporting URL:', error);
            alert("Error reporting URL. Please try again later.");
            // Reset status banner to unknown state
            statusBanner.style.backgroundColor = "blue";
            statusBanner.textContent = "Unknown";
            resultDiv.textContent = "Welcome to PhiShield";
            checkUrlButton.disabled = false;
        }
    });
});
