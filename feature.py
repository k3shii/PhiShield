import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date, datetime
from urllib.parse import urlparse

class FeatureExtraction:
    def __init__(self, url, skip_whois=False):
        self.features = []
        self.url = url.lower()
        self.domain = ""
        self.whois_response = None
        self.urlparse = None
        self.response = None
        self.soup = None
        self.skip_whois = skip_whois

        try:
            self.response = requests.get(url, timeout=10)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except Exception as e:
            self.response = None
            print(f"Error fetching URL: {e}")

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except Exception as e:
            print(f"Error parsing URL: {e}")

        if not self.skip_whois:
            try:
                self.whois_response = whois.whois(self.domain)
            except Exception as e:
                self.whois_response = None
                print(f"Error fetching WHOIS data: {e}")

        # Extract features
        self.features = [
            self.UsingIp(),
            self.longUrl(),
            self.shortUrl(),
            self.symbol(),
            self.redirecting(),
            self.prefixSuffix(),
            self.SubDomains(),
            self.Https(),
            self.DomainRegLen(),
            self.Favicon(),
            self.NonStdPort(),
            self.HTTPSDomainURL(),
            self.RequestURL(),
            self.AnchorURL(),
            self.LinksInScriptTags(),
            self.ServerFormHandler(),
            self.InfoEmail(),
            self.AbnormalURL(),
            self.WebsiteForwarding(),
            self.StatusBarCust(),
            self.DisableRightClick(),
            self.UsingPopupWindow(),
            self.IframeRedirection(),
            self.AgeofDomain(),
            self.DNSRecording(),
            self.WebsiteTraffic(),
            self.PageRank(),
            self.GoogleIndex(),
            self.LinksPointingToPage(),
            self.StatsReport()
        ]

    # 1. Using IP
    def UsingIp(self):
        try:
            ipaddress.ip_address(self.url)
            return -1  # Suspicious if IP is used
        except ValueError:
            return 1  # Legitimate if no IP is used

    # 2. Long URL
    def longUrl(self):
        length = len(self.url)
        if length < 54:
            return 1
        elif 54 <= length <= 75:
            return 0
        else:
            return -1

    # 3. Shortened URL
    def shortUrl(self):
        # Fetch latest URL shorteners list from GitHub
        response = requests.get('https://raw.githubusercontent.com/PeterDaveHello/url-shorteners/master/list')
        shortened_services = tuple(domain.strip() for domain in response.text.split('\n') 
                                if domain.strip() and not domain.startswith('#'))
        if any(service in self.url for service in shortened_services):
            return -1
        return 1

    # 4. Symbol @
    def symbol(self):
        return -1 if "@" in self.url else 1

    # 5. Redirecting //
    def redirecting(self):
        return -1 if self.url.count('//') > 1 else 1

    # 6. Prefix-Suffix
    def prefixSuffix(self):
        return -1 if '-' in self.domain else 1

    # 7. Subdomains
    def SubDomains(self):
        subdomain_count = self.domain.count('.')
        if subdomain_count == 1:
            return 1
        elif subdomain_count == 2:
            return 0
        else:
            return -1

    # 8. HTTPS
    def Https(self):
        return 1 if self.urlparse.scheme == 'https' else -1

    # 9. Domain Registration Length
    def DomainRegLen(self):
        try:
            expiration_date = self.whois_response.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            age = (expiration_date - datetime.now()).days / 365
            return 1 if age >= 1 else -1
        except:
            return -1

    # 10. Favicon
    def Favicon(self):
        try:
            for link in self.soup.find_all('link', rel='icon'):
                if self.domain not in link['href']:
                    return -1
            return 1
        except:
            return -1

    # 11. Non-Standard Port
    def NonStdPort(self):
        return -1 if ':' in self.domain else 1

    # 12. HTTPS in Domain URL
    def HTTPSDomainURL(self):
        return -1 if 'https' in self.domain else 1

    # 13. Request URL
    def RequestURL(self):
        try:
            total, suspicious = 0, 0
            for tag in ['img', 'audio', 'embed', 'iframe']:
                for element in self.soup.find_all(tag, src=True):
                    total += 1
                    if self.domain not in element['src']:
                        suspicious += 1
            if total == 0:
                return 1
            percentage = (suspicious / total) * 100
            if percentage < 22:
                return 1
            elif percentage < 61:
                return 0
            else:
                return -1
        except:
            return -1

    # 14. Anchor URL
    def AnchorURL(self):
        try:
            total, unsafe = 0, 0
            for a in self.soup.find_all('a', href=True):
                total += 1
                if any(x in a['href'] for x in ['#', 'javascript', 'mailto']) or self.domain not in a['href']:
                    unsafe += 1
            if total == 0:
                return 1
            percentage = (unsafe / total) * 100
            if percentage < 31:
                return 1
            elif percentage < 67:
                return 0
            else:
                return -1
        except:
            return -1

    # 15. Links in Script Tags
    def LinksInScriptTags(self):
        try:
            total, suspicious = 0, 0
            for tag in ['link', 'script']:
                for element in self.soup.find_all(tag, href=True):
                    total += 1
                    if self.domain not in element['href']:
                        suspicious += 1
            if total == 0:
                return 1
            percentage = (suspicious / total) * 100
            if percentage < 17:
                return 1
            elif percentage < 81:
                return 0
            else:
                return -1
        except:
            return -1

    # 16. Server Form Handler
    def ServerFormHandler(self):
        try:
            forms = self.soup.find_all('form', action=True)
            if not forms:
                return 1
            for form in forms:
                action = form['action']
                if action in ["", "about:blank"] or self.domain not in action:
                    return -1
            return 1
        except:
            return -1

    # 17. Info Email
    def InfoEmail(self):
        return -1 if re.search(r"mailto:", self.response.text) else 1

    # 18. Abnormal URL
    def AbnormalURL(self):
        return -1 if self.response.text == str(self.whois_response) else 1

    # 19. Website Forwarding
    def WebsiteForwarding(self):
        try:
            redirection_count = len(self.response.history)
            if redirection_count <= 1:
                return 1
            elif redirection_count <= 4:
                return 0
            else:
                return -1
        except:
            return -1

    # 20. Status Bar Customization
    def StatusBarCust(self):
        return -1 if re.search(r"onmouseover", self.response.text) else 1

    # 21. Disable Right Click
    def DisableRightClick(self):
        return -1 if re.search(r"event.button ?== ?2", self.response.text) else 1

    # 22. Using Popup Window
    def UsingPopupWindow(self):
        return -1 if re.search(r"alert\(", self.response.text) else 1

    # 23. Iframe Redirection
    def IframeRedirection(self):
        return -1 if re.search(r"<iframe", self.response.text) else 1

    # 24. Age of Domain
    def AgeofDomain(self):
        try:
            creation_date = self.whois_response.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            age = (date.today() - creation_date).days / 30
            return 1 if age >= 6 else -1
        except:
            return -1

    # 25. DNS Recording
    def DNSRecording(self):
        return self.AgeofDomain()

    # 26. Website Traffic
    def WebsiteTraffic(self):
        try:
            rank = BeautifulSoup(
                urllib.request.urlopen(f"http://data.alexa.com/data?cli=10&dat=s&url={self.url}").read(),
                "xml"
            ).find("REACH")['RANK']
            return 1 if int(rank) < 100000 else 0
        except:
            return -1

    # 27. PageRank
    def PageRank(self):
        try:
            response = requests.post("https://www.checkpagerank.net/index.php", {"name": self.domain})
            rank = int(re.search(r"Global Rank: ([0-9]+)", response.text).group(1))
            return 1 if rank < 100000 else -1
        except:
            return -1

    # 28. Google Index
    def GoogleIndex(self):
        try:
            results = list(search(self.url, num_results=5))
            return 1 if results else -1
        except:
            return -1

    # 29. Links Pointing to Page
    def LinksPointingToPage(self):
        try:
            links = len(re.findall(r"<a href=", self.response.text))
            if links == 0:
                return 1
            elif links <= 2:
                return 0
            else:
                return -1
        except:
            return -1

    # 30. Stats Report
    def StatsReport(self):
        try:
            # Fetch latest blacklisted domains from GitHub
            response = requests.get('https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-NEW-today.txt')
            blacklisted_urls = [domain.strip() for domain in response.text.split('\n') if domain.strip() and not domain.startswith('#')]
            # Fetch latest blacklisted IPs from GitHub
            response = requests.get('https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-IPs-ACTIVE.txt')
            blacklisted_ips = [ip.strip() for ip in response.text.split('\n') if ip.strip() and not ip.startswith('#')]
            ip_address = socket.gethostbyname(self.domain)
            # Check if domain or IP matches any blacklisted entries
            if any(bl_url in self.url for bl_url in blacklisted_urls) or ip_address in blacklisted_ips:
                return 1  # Return 1 if URL or IP is found in blacklist (phishing)
            return -1  # Return -1 if not found in any blacklist (legitimate)
        except:
            return -1  # Return -1 on error to be safe

    def getFeaturesList(self):
        return self.features
