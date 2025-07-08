#importing required libraries

from flask import Flask, request, render_template, jsonify
import numpy as np
import pandas as pd
from sklearn import metrics 
import warnings
import pickle
import json
import os
from datetime import datetime
warnings.filterwarnings('ignore')
from feature import FeatureExtraction
from flask_cors import CORS

file = open("model.pkl","rb")
gbc = pickle.load(file)
file.close()

app = Flask(__name__, template_folder='.')

# Enable CORS for the Flask app with specific origin
CORS(app, resources={r"/*": {"origins": ["chrome-extension://bjkfelbgeebiljecippblmjfcnnidkmo", "http://127.0.0.1:5000"]}})

def load_json_file(filename):
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return []
    return []

def save_json_file(filename, data):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)

def load_pending_reports():
    return load_json_file('pending.json')

def save_pending_reports(reports):
    save_json_file('pending.json', reports)

def load_blacklist():
    return load_json_file('blacklist.json')

def save_blacklist(blacklist):
    save_json_file('blacklist.json', blacklist)

def load_whitelist():
    return load_json_file('whitelist.json')

def save_whitelist(whitelist):
    save_json_file('whitelist.json', whitelist)

def verify_admin_key(admin_key):
    # Replace this with proper admin authentication
    return admin_key == "your-secure-admin-key"

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        try:
            url = request.form.get("url")
            if not url:
                return jsonify({"error": "No URL provided"}), 400

            # Check if URL is in blacklist
            blacklist = load_blacklist()
            if any(entry["url"] == url for entry in blacklist):
                return jsonify({
                    "xx": 0,
                    "url": url,
                    "prediction": -1,
                    "message": "URL is blacklisted"
                })

            # Check if URL is in whitelist
            whitelist = load_whitelist()
            if any(entry["url"] == url for entry in whitelist):
                return jsonify({
                    "xx": 1,
                    "url": url,
                    "prediction": 1,
                    "message": "URL is whitelisted"
                })

            # Skip WHOIS check if it's causing issues
            obj = FeatureExtraction(url, skip_whois=True)
            x = np.array(obj.getFeaturesList()).reshape(1,30) 

            y_pred = gbc.predict(x)[0]
            y_pro_phishing = gbc.predict_proba(x)[0,0]
            y_pro_non_phishing = gbc.predict_proba(x)[0,1]
            
            return jsonify({
                "xx": round(y_pro_non_phishing, 2),
                "url": url,
                "prediction": int(y_pred)
            })
        except Exception as e:
            print(f"Error processing request: {str(e)}")
            return jsonify({"error": str(e)}), 500
            
    return render_template("popup.html", xx=-1)

@app.route("/report", methods=["POST"])
def report_url():
    try:
        data = request.get_json()
        url = data.get("url")
        
        if not url:
            return jsonify({"error": "No URL provided"}), 400

        # Check if URL is already in blacklist
        blacklist = load_blacklist()
        if any(entry["url"] == url for entry in blacklist):
            return jsonify({"message": "URL is already blacklisted"}), 200

        # Check if URL is already in whitelist
        whitelist = load_whitelist()
        if any(entry["url"] == url for entry in whitelist):
            return jsonify({"message": "URL is already whitelisted"}), 200

        # Load existing reports
        reports = load_pending_reports()
        
        # Check if URL is already reported
        if any(report["url"] == url for report in reports):
            return jsonify({"message": "URL already reported"}), 200

        # Add new report
        new_report = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "status": "pending"
        }
        
        reports.append(new_report)
        save_pending_reports(reports)
        
        return jsonify({"message": "URL reported successfully"}), 200
        
    except Exception as e:
        print(f"Error processing report: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/whitelist", methods=["POST", "GET", "DELETE"])
def manage_whitelist():
    if request.method == "POST":
        try:
            data = request.get_json()
            url = data.get("url")
            
            if not url:
                return jsonify({"error": "No URL provided"}), 400

            # Check if URL is already in whitelist
            whitelist = load_whitelist()
            if any(entry["url"] == url for entry in whitelist):
                return jsonify({"message": "URL already whitelisted"}), 200

            # Add to whitelist
            new_entry = {
                "url": url,
                "timestamp": datetime.now().isoformat(),
                "source": "user_bookmark"
            }
            
            whitelist.append(new_entry)
            save_whitelist(whitelist)
            
            return jsonify({"message": "URL whitelisted successfully"}), 200
            
        except Exception as e:
            print(f"Error processing whitelist: {str(e)}")
            return jsonify({"error": str(e)}), 500
    elif request.method == "GET":
        whitelist = load_json_file("whitelist.json")
        return jsonify(whitelist)
    elif request.method == "DELETE":
        try:
            url = request.json.get("url")
            if not url:
                return jsonify({"error": "No URL provided"}), 400

            whitelist = load_json_file("whitelist.json")
            whitelist = [entry for entry in whitelist if entry["url"] != url]
            
            with open("whitelist.json", "w") as f:
                json.dump(whitelist, f, indent=4)
            
            return jsonify({"message": "URL removed from whitelist"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

# Admin endpoints
@app.route("/admin/pending", methods=["GET", "DELETE"])
def admin_get_pending():
    try:
        admin_key = request.headers.get("X-Admin-Key")
        if not verify_admin_key(admin_key):
            return jsonify({"error": "Unauthorized"}), 401

        if request.method == "GET":
            reports = load_pending_reports()
            return jsonify(reports)
        
        elif request.method == "DELETE":
            data = request.get_json()
            url = data.get("url")
            
            if not url:
                return jsonify({"error": "No URL provided"}), 400

            reports = load_pending_reports()
            reports = [report for report in reports if report["url"] != url]
            save_pending_reports(reports)
            
            return jsonify({"message": "URL removed from pending reports successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/blacklist", methods=["GET", "POST", "DELETE"])
def admin_blacklist():
    try:
        admin_key = request.headers.get("X-Admin-Key")
        if not verify_admin_key(admin_key):
            return jsonify({"error": "Unauthorized"}), 401

        if request.method == "GET":
            blacklist = load_blacklist()
            return jsonify(blacklist)

        elif request.method == "POST":
            data = request.get_json()
            url = data.get("url")
            
            if not url:
                return jsonify({"error": "No URL provided"}), 400

            # Load pending reports
            reports = load_pending_reports()
            
            # Find the report
            report_index = next((i for i, r in enumerate(reports) if r["url"] == url), None)
            
            if report_index is not None:
                # Remove from pending reports
                report = reports.pop(report_index)
                save_pending_reports(reports)

            # Add to blacklist
            blacklist = load_blacklist()
            new_entry = {
                "url": url,
                "timestamp": datetime.now().isoformat(),
                "source": "admin_blacklist"
            }
            
            blacklist.append(new_entry)
            save_blacklist(blacklist)
            
            return jsonify({"message": "URL added to blacklist successfully"}), 200

        elif request.method == "DELETE":
            data = request.get_json()
            url = data.get("url")
            
            if not url:
                return jsonify({"error": "No URL provided"}), 400

            blacklist = load_blacklist()
            blacklist = [entry for entry in blacklist if entry["url"] != url]
            save_blacklist(blacklist)
            
            return jsonify({"message": "URL removed from blacklist successfully"}), 200

    except Exception as e:
        print(f"Error processing blacklist: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/admin/whitelist", methods=["GET", "POST", "DELETE"])
def admin_whitelist():
    try:
        admin_key = request.headers.get("X-Admin-Key")
        if not verify_admin_key(admin_key):
            return jsonify({"error": "Unauthorized"}), 401

        if request.method == "GET":
            whitelist = load_whitelist()
            return jsonify(whitelist)

        elif request.method == "POST":
            data = request.get_json()
            url = data.get("url")
            
            if not url:
                return jsonify({"error": "No URL provided"}), 400

            # Load pending reports
            reports = load_pending_reports()
            
            # Find the report
            report_index = next((i for i, r in enumerate(reports) if r["url"] == url), None)
            
            if report_index is not None:
                # Remove from pending reports
                report = reports.pop(report_index)
                save_pending_reports(reports)

            # Add to whitelist
            whitelist = load_whitelist()
            new_entry = {
                "url": url,
                "timestamp": datetime.now().isoformat(),
                "source": "admin_whitelist"
            }
            
            whitelist.append(new_entry)
            save_whitelist(whitelist)
            
            return jsonify({"message": "URL added to whitelist successfully"}), 200

        elif request.method == "DELETE":
            data = request.get_json()
            url = data.get("url")
            
            if not url:
                return jsonify({"error": "No URL provided"}), 400

            whitelist = load_whitelist()
            whitelist = [entry for entry in whitelist if entry["url"] != url]
            save_whitelist(whitelist)
            
            return jsonify({"message": "URL removed from whitelist successfully"}), 200

    except Exception as e:
        print(f"Error processing whitelist: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/admin", methods=["GET"])
def admin_dashboard():
    return render_template("admin.html")

if __name__ == "__main__":
    app.run(debug=True, host='127.0.0.1', port=5000)