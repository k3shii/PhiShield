# PhiShield - Intelligence-Based Phishing Site Detection

PhiShield is an intelligence-based web extension that detects phishing URLs using machine learning algorithms. The system consists of a Flask backend API and a Chrome extension frontend. (This project is developed as a Final Year Project for educational purposes.)

## Tools and Libraries

**Required Python Libraries** (specified in `requirements.txt`):

- beautifulsoup4==4.13.4
- Flask==3.1.0
- flask-cors==5.0.1
- googlesearch-python==1.3.0
- numpy==2.2.5
- pandas==2.2.3
- requests==2.32.3
- scikit-learn==1.6.1
- whois==1.20240129.2

## Dataset Information

The project includes a pre-trained machine learning model (`model.pkl`) and uses the dataset (`phishing.csv`) for training. The dataset contains:

- 11,056 URL samples
- 30 features extracted from each URL
- Binary classification (phishing vs legitimate)

**Dataset Source:** https://www.kaggle.com/datasets/eswarchandt/phishing-website-detector

## Project Structure

```
PhiShield_FYP2/
├── app.py                 # Flask backend server
├── feature.py            # Feature extraction module
├── model.pkl             # Trained ML model
├── phishing.csv          # Training dataset
├── requirements.txt      # Python dependencies
├── manifest.json         # Chrome extension manifest
├── popup.html           # Main extension popup interface
├── popup.js             # Extension popup logic
├── background.js        # Extension background script
├── content.js           # Extension content script
├── admin.html           # Admin dashboard
├── bookmark-list.html   # Bookmark management
├── bookmark-list.js     # Bookmark logic
├── blacklist.json       # Blacklisted URLs
├── whitelist.json       # Whitelisted URLs
├── pending.json         # Pending reports
├── img/                 # Extension icons
├── libs/                # External libraries
└── web/                 # Web interface files
```

## Installation Instructions

### Step 1: Clone or Download the Project

**Option 1: Using Git (Recommended)**

```bash
git clone https://github.com/k3shii/PhiShield.git
cd PhiShield
```

**Option 2: Manual Download**

- Download the project files to your local machine
- Extract all files to a directory of your choice

### Step 2: Set Up Python Environment

1. Open Command Prompt (Windows)
2. Navigate to the project directory (if not already there):

   ```bash
   cd PhiShield
   ```
3. Create a virtual environment (recommended):

   ```bash
   python -m venv venv
   ```
4. Activate the virtual environment:

   ```bash
   venv\Scripts\activate
   ```

### Step 3: Install Required Libraries

- Install all required packages:
  ```bash
  pip install -r requirements.txt
  ```

## Running the Application

### Step 1: Start the Flask Backend Server

1. Open Command Prompt (Windows)
2. Navigate to the project directory (if not already there):

   ```bash
   cd PhiShield_FYP2
   ```
3. Activate virtual environment (if not already activated):

   ```bash
   venv\Scripts\activate
   ```
4. Run the Flask application with the -B flag to disable bytecode generation:

   ```bash
   python -B app.py
   ```
5. You should see output similar to:

   ```
   * Running on http://127.0.0.1:5000
   * Debug mode: off
   ```
6. The server is now running on: http://127.0.0.1:5000
7. Keep this terminal window open while using the application
8. To stop the server, press `Ctrl+C` in the terminal

### Step 2: Install the Chrome Extension

1. Open Google Chrome browser
2. Type `chrome://extensions/` in the address bar and press Enter
3. In the top-right corner of the extensions page, toggle ON the "Developer mode" switch
4. After enabling Developer mode, you will see three new buttons appear: "Load unpacked", "Pack extension", and "Update"
5. Click the "Load unpacked" button
6. A file dialog will open - navigate to your PhiShield project folder
7. Select the entire PhiShield folder (not individual files)
8. Click "Select Folder"
9. The PhiShield extension should now appear in your extensions list with the name "PhiShield"
10. If you see any errors, click the "Reload" button on the extension card

### Step 3: Use the Application

1. Look for the PhiShield extension icon in your Chrome toolbar (top-right corner)
2. If you don't see it, click the puzzle piece icon (extensions menu) and pin PhiShield
3. Click on the PhiShield extension icon to open the popup
4. In the popup window, enter a URL to check for phishing (e.g., https://example.com)
5. Click "Check URL" or press Enter
6. The system will analyze the URL and display results:
   - **Green**: Safe/Legitimate URL
   - **Red**: Phishing/Suspicious URL
   - **Yellow**: Uncertain/Under review
7. Use the "Add to Bookmarks" feature to save trusted URLs
8. Use the "Report URL" feature to report suspicious URLs for admin review

## Administrative Features

**Access Admin Dashboard:**

1. Open browser and go to: http://127.0.0.1:5000/admin
2. Username: `admin` Password: `admin123` (this can be changed in `admin.html`)
3. Use admin key: `"your-secure-admin-key"` (change this in production)

**Admin Features:**

- View pending URL reports
- Manage blacklist and whitelist
- Approve or reject reported URLs
- Monitor system activity

## API Endpoints

**Backend API Endpoints:**

- `POST /` - URL phishing detection
- `POST /report` - Report suspicious URL
- `POST /whitelist` - Add URL to whitelist
- `GET /whitelist` - Get whitelist
- `DELETE /whitelist` - Remove URL from whitelist
- `GET /admin/pending` - Get pending reports (admin)
- `POST /admin/blacklist` - Add URL to blacklist (admin)
- `GET /admin/blacklist` - Get blacklist (admin)
- `DELETE /admin/blacklist` - Remove URL from blacklist (admin)

## Verification Steps

After installation, verify everything is working correctly:

### 1. Verify Flask Server

- Open browser and go to: http://127.0.0.1:5000
- You should see the PhiShield popup interface
- If you see "Connection refused", the server is not running

### 2. Verify Chrome Extension

- Check `chrome://extensions/` page
- PhiShield should be listed and enabled
- No red error messages should be visible
- Extension icon should appear in toolbar

### 3. Test URL Detection

- Click PhiShield extension icon
- Enter a known safe URL (e.g., https://www.google.com)
- Should return "Safe" or "Legitimate" result with confidence
- Enter a known phishing URL for testing

### 4. Test Admin Dashboard

- Go to: http://127.0.0.1:5000/admin
- Enter username (`admin`) and password (`admin123`)
- Should show admin interface with pending

## Version Information

- **PhiShield Version:** 1.0
- **Last Updated:** July 2025
- **Compatible with:** Python 3.8+, Google Chrome, Microsoft Edge
