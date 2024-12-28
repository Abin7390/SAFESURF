import ipaddress
import re
import urllib.request
import socket
import requests
from bs4 import BeautifulSoup
from googlesearch import search
import whois
from datetime import date
from urllib.parse import urlparse, urlunparse
import os


class FeatureExtraction:
    report = {}
    features=[]

    def __init__(self, url):
        self.report_dict = {}
        self.url = url
        self.urlparse = urlparse(url)
        self.domain = '{uri.scheme}://{uri.netloc}'.format(uri=urlparse(self.url))
        try:
            self.whois_response = whois.whois(self.domain)
        except:
            self.whois_response = None
            
        self.scheme = 'http://'  # Default scheme if missing
        if not self.urlparse.scheme:
            self.url = f"{self.scheme}{url}"
        self.urlparse = urlparse(self.url)
        try:
            response = requests.get(self.url)
            if 200 <= response.status_code < 300:
                self.response = response
                self.soup = BeautifulSoup(response.text, 'html.parser')
                self.success = 1
            else:
                self.response = None
                self.soup = None
                self.success = 0
        except requests.RequestException as e:
            self.response = None
            self.soup = None
            self.success = 0
            self.report[self.url] = f"Failed to retrieve URL content for favicon check: {e}"
            print(f"Request failed: {e}")
        
        # Number of attempts (this would ideally be set differently, based on actual request attempts)
        self.i = 1  # Assuming one attempt for this example

        
        # self.scheme = self.urlparse.scheme
        # self.path = self.urlparse.path
        # self.whois_response = self.get_whois(self.domain)
        # self.soup = self.get_soup(self.url)
        # self.success = None  # or any default value you wish to assign
        # self.i = None  # or any default value you wish to assign

        

        try:
            self.response = requests.get(url)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except:
            pass

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except:
            pass

        try:
            self.whois_response = whois.whois(self.domain)
        except:
            pass

        self.features.clear()
        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Hppts())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())
        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.StatusBarCust())
        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DNSRecording())
        # self.features.append(self.WebsiteTraffic())
        # self.features.append(self.PageRank())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.StatsReport())

    def UsingIp(self):
        try:
            ipaddress.ip_address(self.urlparse.hostname)
            result = -1
            report_message = "The URL contains an IP address instead of a domain name, so it might be malicious."
        except ValueError:
            result = 1
            report_message = "The URL contains a domain name, so it's likely a safe URL."

       # Store in the report and dictionary
        FeatureExtraction.report[self.url] = report_message
        self.report_dict["1. UsingIp"] = report_message
        return result

    def longUrl(self):
        # Define a threshold for the URL length
        threshold_length = 54
        if len(self.url) > threshold_length:
            result = -1
            report_message = "The URL is considered long which might be suspicious."
        else:
            result = 1
            report_message = "The URL is not considered long, it's within the normal range."

        # Store in the report
        FeatureExtraction.report[self.url] = report_message
        self.report_dict["2. longUrl"] = report_message
        return result
    def shortUrl(self):
        # Define a regular expression pattern for short URLs
        short_url_patterns = re.compile(
            r"(bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"
            r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"
            r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"
            r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|"
            r"db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|"
            r"q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|"
            r"x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net)",
            re.IGNORECASE)
        
        # Check if the domain of the URL matches the pattern for a short URL
        if re.search(short_url_patterns, self.urlparse.netloc):
            result = -1
            report_message = "The URL matches a known short URL pattern, which might be suspicious."
        else:
            result = 1
            report_message = "The URL does not match any known short URL patterns, so it's less likely to be suspicious."

        # Store in the report
        FeatureExtraction.report[self.url] = report_message
        self.report_dict["3. shortUrl"] = report_message
        return result

    def symbol(self):
        # Check if the '@' symbol is present in the URL
        if "@" in self.url:
            result = -1
            report_message = "The URL contains the '@' symbol, which might be suspicious."
        else:
            result = 1
            report_message = "The URL does not contain the '@' symbol, so it's less likely to be suspicious."

        # Store in the report
        FeatureExtraction.report[self.url] = report_message
        self.report_dict["4. symbol"] = report_message

        return result

    def redirecting(self):
        # Check if there is '//' in the URL which appears later than after the protocol
        if self.url.rfind('//') > 6:
            result = -1
            report_message = "The URL contains '//' after the protocol, suggesting a redirection, which might be suspicious."
        else:
            result = 1
            report_message = "The URL does not contain redirection '//' after the protocol, so it's less likely to be suspicious."

        # Store in the report
        FeatureExtraction.report[self.url] = report_message
        self.report_dict["5. redirecting"] = report_message
        return result

    def prefixSuffix(self):
        # Check if there is a '-' in the domain name
        if '-' in self.domain:
            result = -1
            report_message = "The domain name contains a '-' (hyphen), which might be suggestive of a phishing attempt."
        else:
            result = 1
            report_message = "The domain name doesn't contain a '-' (hyphen), which is less likely to be a characteristic of phishing attempts."
        
        # Store in the report
        FeatureExtraction.report[self.url] = report_message
        self.report_dict["6. prefixSuffix"] = report_message
        return result

    def SubDomains(self):
        # Count the number of '.' in the domain part of the URL
        dot_count = self.domain.count(".")
        
        # Determine if the number of dots indicates presence of subdomains and report accordingly
        if dot_count > 2:
            result = -1
            report_message = "The domain name contains multiple '.' which could indicate the presence of subdomains, potentially suspicious."
        elif dot_count == 2:
            result = 0
            report_message = "The domain name might contain a single subdomain or none, which could be normal for some legitimate domains."
        else:
            result = 1
            report_message = "The domain name does not contain subdomains, it's less likely to be suspicious."
        
        # Store in the report
        FeatureExtraction.report[self.url] = report_message
        self.report_dict["7. SubDomains"] = report_message
        return result

    def Hppts(self):
        # Check if the URL's scheme is HTTPS
        if self.urlparse.scheme == 'https':
            result = 1
            report_message = "The URL uses HTTPS which is the secure version of HTTP, so it's less likely to be suspicious."
        else:
            result = -1
            report_message = "The URL does not use HTTPS which might be less secure, so it could be suspicious."
        
        # Store in the report
        FeatureExtraction.report[self.url] = report_message
        self.report_dict["8. Hppts"] = report_message
        return result

    def DomainRegLen(self):
        if self.whois_response is None or self.whois_response.creation_date is None or self.whois_response.expiration_date is None:
            report_message = "No WHOIS data was retrieved for the domain, or necessary data was missing."
            result = -1  # You could use a specific code to indicate missing data.
        else:
            try:
                creation_date = self.whois_response.creation_date
                expiration_date = self.whois_response.expiration_date

                # Handling the possibility of multiple dates as returned by some WHOIS responses
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                if isinstance(expiration_date, list):
                    expiration_date = expiration_date[0]

                # Calculate domain age in months
                domain_age_in_months = (expiration_date.year - creation_date.year) * 12 + (expiration_date.month - creation_date.month)
                
                # Checking if domain registration length is at least 12 months
                if domain_age_in_months >= 12:
                    report_message = "The domain has been registered for a long time, which is less likely to be suspicious."
                    result = 1
                else:
                    report_message = "The domain registration length is less than 12 months, which might be suspicious."
                    result = -1
                    
            except AttributeError as e:
                # Catch any attribute errors encountered when accessing parts of the WHOIS response
                report_message = f"An attribute error occurred when processing WHOIS data: {str(e)}"
                result = -1

        # Store in the report
        FeatureExtraction.report[self.url] = report_message
        self.report_dict["9. DomainRegLen"] = report_message
        return result

    def Favicon(self):
        
        result = -1

        if self.soup is None:
            report_message = "Failed to parse the HTML of the page."
        else:
            try:
                # Search for any common favicon rel attribute patterns
                favicon_links = self.soup.find_all('link', rel=lambda value: value and 'icon' in value.lower())
                favicon_found = len(favicon_links) > 0
                if favicon_found:
                    result = 1
                    report_message = "A favicon link is found within the page, which is expected for legitimate sites."
                else:
                    # Additional check for default favicon location
                    default_favicon_url = f"{self.urlparse.scheme}://{self.urlparse.netloc}/favicon.ico"
                    response = requests.head(default_favicon_url)
                    if response.status_code == 200:
                        result = 1
                        report_message = "A default favicon.ico is found, which is expected for legitimate sites."
                    else:
                        report_message = "No favicon link found in the page, which might be suspicious."
            except Exception as e:
                report_message = f"An error occurred while searching for the favicon: {e}"

        FeatureExtraction.report[self.url] = report_message
        self.report_dict["10. Favicon"] = report_message
        return result

    def NonStdPort(self):
        report_message = ""
        result = 1  # Assume the port is standard initially

        try:
            port = self.urlparse.port
            if port is None:
                # Assign default ports based on the scheme
                if self.urlparse.scheme == 'https':
                    port = 443
                elif self.urlparse.scheme == 'http':
                    port = 80

            print(port)
            if port and port not in [80, 443]:
                result = -1
                report_message = "Non-standard port found, which might be suspicious."
            else:
                report_message = "Standard port or no port specified, which is expected for legitimate sites."
        except Exception as e:
            result = -1
            report_message = f"An error occurred while checking the URL port: {e}"

        FeatureExtraction.report[self.url] = report_message
        self.report_dict["11. NonStdPort"] = report_message
        return result

    def HTTPSDomainURL(self):
        report_message = ""
        try:
            # Check if the URL uses HTTPS scheme
            if self.urlparse.scheme == 'https':
                result = 1
                report_message = "URL uses HTTPS scheme, which is expected for a valid site."
            else:
                result = -1
                report_message = "URL does not use HTTPS scheme, which might be suspicious."
        except Exception as e:
            result = -1
            report_message = f"An error occurred while checking the URL scheme: {e}"

        FeatureExtraction.report[self.url] = report_message
        self.report_dict["12. HTTPSDomainURL"] = report_message
        return result

    def RequestURL(self):
        report_message = ""
        try:
            success = 0
            i = 0

            for img in self.soup.find_all('img', src=True):
                dots = [x.start(0) for x in re.finditer(r'\.', img['src'])]
                #print(f"IMG SRC: {img['src']} - {'Internal' if self.url in img['src'] or self.domain in img['src'] or len(dots) == 1 else 'External'}")
                if self.url in img['src'] or self.domain in img['src'] or len(dots) == 1:
                    success += 1
                i += 1

            for audio in self.soup.find_all('audio', src=True):
                dots = [x.start(0) for x in re.finditer(r'\.', audio['src'])]
                #print(f"AUDIO SRC: {audio['src']} - {'Internal' if self.url in audio['src'] or self.domain in audio['src'] or len(dots) == 1 else 'External'}")
                if self.url in audio['src'] or self.domain in audio['src'] or len(dots) == 1:
                    success += 1
                i += 1

            for embed in self.soup.find_all('embed', src=True):
                dots = [x.start(0) for x in re.finditer(r'\.', embed['src'])]
                #print(f"EMBED SRC: {embed['src']} - {'Internal' if self.url in embed['src'] or self.domain in embed['src'] or len(dots) == 1 else 'External'}")
                if self.url in embed['src'] or self.domain in embed['src'] or len(dots) == 1:
                    success += 1
                i += 1

            for iframe in self.soup.find_all('iframe', src=True):
                dots = [x.start(0) for x in re.finditer(r'\.', iframe['src'])]
                #print(f"IFRAME SRC: {iframe['src']} - {'Internal' if self.url in iframe['src'] or self.domain in iframe['src'] or len(dots) == 1 else 'External'}")
                if self.url in iframe['src'] or self.domain in iframe['src'] or len(dots) == 1:
                    success += 1
                i += 1

            try:
                if i > 0:
                    percentage = success / float(i) * 100
                    #print(f"Percentage of internal URLs: {percentage}")
                    if percentage < 22.0:
                        result = -1
                        report_message = "Low percentage of internal URLs."
                    elif 22.0 <= percentage < 61.0:
                        result = 0
                        report_message = "Moderate percentage of internal URLs."
                    else:
                        result = 1
                        report_message = "High percentage of internal URLs."
                else:
                    result = -1
                    report_message = "No valid URLs found."
            except Exception as e:
                result = 0
                report_message = f"Error in calculating percentage of internal URLs: {e}"
        except Exception as e:
            result = -1
            report_message = f"Error in processing request URLs: {e}"

        FeatureExtraction.report[self.url] = report_message
        self.report_dict["13. RequestURL"] = report_message
        return result

    def AnchorURL(self):
        report_message = ""
        result = 1
        try:
            i, unsafe = 0, 0
            for a in self.soup.find_all('a', href=True):
                print(f"Checking link: {a['href']}")  # Debugging line
                if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (self.url in a['href'] or self.domain in a['href']):
                    unsafe += 1
                i += 1

            if i == 0:
                report_message = "No anchor tags found."
                result = -1
            else:
                percentage = unsafe / float(i) * 100
                print(f"Percentage of unsafe links: {percentage}%")  # Debugging line
                if percentage < 31.0:
                    result = 1
                    report_message = "Majority of anchor tags are safe."
                elif 31.0 <= percentage < 67.0:
                    result = 0
                    report_message = "A significant number of anchor tags may be unsafe."
                else:
                    result = -1
                    report_message = "Most anchor tags are unsafe."

        except Exception as e:
            result = -1
            report_message = f"An error occurred while checking anchor tags: {e}"

        FeatureExtraction.report[self.url] = report_message
        self.report_dict["14. AnchorURL"] = report_message
        return result

    def LinksInScriptTags(self):
        report_message = ""
        try:
            success = 0
            total = 0

            # Check for links in 'link' and 'script' tags
            for tag in ['link', 'script']:
                for item in self.soup.find_all(tag, href=True):
                    if self.url in item['href'] or self.domain in item['href'] or '.' not in item['href']:
                        success += 1
                    total += 1

            # Calculate the percentage
            percentage = (success / total) * 100 if total > 0 else 0
            
            # Determine result and report message based on percentage
            if percentage < 17.0:
                result = 1
                report_message = "Low percentage of links in 'link' and 'script' tags."
            elif 17.0 <= percentage < 81.0:
                result = 0
                report_message = "Moderate percentage of links in 'link' and 'script' tags."
            else:
                result = -1
                report_message = "High percentage of links in 'link' and 'script' tags."

        except Exception as e:
            result = -1
            report_message = f"An error occurred while processing links in 'link' and 'script' tags: {e}"

        # Store the report message
        FeatureExtraction.report[self.url] = report_message
        self.report_dict["15. LinksInScriptTags"] = report_message
        return result

    def ServerFormHandler(self):
        report_message = ""
        result = 1  # Assume no forms or valid forms initially

        def is_domain_resolvable(url):
            try:
                domain = urlparse(url).netloc
                socket.gethostbyname(domain)
                return True
            except socket.error:
                return False

        if not is_domain_resolvable(self.url):
            report_message = "Domain is not resolvable."
            result = -1
        else:
            try:
                if not self.soup:
                    # Handle case where soup is None
                    report_message = "Failed to retrieve or parse the page."
                    return -1

                forms = self.soup.find_all('form', action=True)
                if not forms:
                    result = 1
                    report_message = "No forms found on the page, which is expected for a legitimate site."
                else:
                    for form in forms:
                        if form['action'] == "" or form['action'] == "about:blank":
                            result = -1
                            report_message = "Form found with an empty or 'about:blank' action attribute, which may be suspicious."
                            break
                    else:
                        result = 0
                        report_message = "All forms have valid action attributes."

            except Exception as e:
                result = -1
                report_message = f"An error occurred while checking forms on the page: {e}"

        # Store the report message
        FeatureExtraction.report[self.url] = report_message
        self.report_dict["16. ServerFormHandler"] = report_message
        return result
    
    def InfoEmail(self):
        report_message = ""
        result = 1  # Assume no email info found initially

        def is_domain_resolvable(url):
            try:
                domain = urlparse(url).netloc
                socket.gethostbyname(domain)
                return True
            except socket.error:
                return False

        if not is_domain_resolvable(self.url):
            report_message = "Domain is not resolvable."
            result = -1
        else:
            try:
                if not self.soup:
                    result = -1
                    report_message = "Failed to retrieve or parse HTML content."
                elif re.findall(r'mailto:', self.soup.prettify()):
                    result = -1
                    report_message = "Email-related information found in the HTML content, which may indicate a potential phishing site."
                else:
                    report_message = "No email-related information found in the HTML content, which is expected for legitimate sites."

            except Exception as e:
                result = -1
                report_message = f"An error occurred while checking the HTML content for email information: {e}"

        # Store the report message
        FeatureExtraction.report[self.url] = report_message
        self.report_dict["17. InfoEmail"] = report_message
        return result
        

    def AbnormalURL(self):
        report_message = ""
        result = 1  # Assume no abnormal characters found initially

        try:
            # Check for abnormal characters in the URL
            if any(char in self.url for char in ['@', '?', '%', '&', '=', '_']):
                result = -1
                report_message = "The URL contains abnormal characters, which may be suspicious."
            else:
                report_message = "No abnormal characters found in the URL, which is expected for legitimate sites."

        except Exception as e:
            result = -1
            report_message = f"An error occurred while checking the URL for abnormal characters: {e}"

        # Store the report message
        FeatureExtraction.report[self.url] = report_message
        self.report_dict["18. AbnormalURL"] = report_message
        return result

    def WebsiteForwarding(self):
        report_message = ""
        result = 1  # Assume no suspicious characters found initially

        try:
            # Check if '1' is in the URL
            if '1' in self.url:
                result = -1
                report_message = "The URL contains '1', which may indicate website forwarding or obfuscation."
            else:
                report_message = "No suspicious characters found in the URL, which is expected for legitimate sites."

        except Exception as e:
            result = -1
            report_message = f"An error occurred while checking the URL for suspicious characters: {e}"

        # Store the report message
        FeatureExtraction.report[self.url] = report_message
        self.report_dict["19. WebsiteForwarding"] = report_message
        return result

    def StatusBarCust(self):
        report_message = ""
        result = 1  # Assume no suspicious patterns found initially

        try:
            # Check if 'status' is in the URL
            if 'status' in self.url:
                result = -1
                report_message = "The URL contains 'status', which may indicate a suspicious custom status bar."
            else:
                # Check the HTML content for suspicious JavaScript patterns
                if self.response:
                    if re.findall(r"<script>.*onmouseover.*</script>", self.response.text, re.IGNORECASE):
                        result = -1
                        report_message = "The HTML content contains 'onmouseover' event handlers in <script> tags, which may indicate malicious JavaScript."
                    else:
                        report_message = "No suspicious JavaScript patterns found in the HTML content."
                else:
                    report_message = "No response from the server; unable to check for JavaScript patterns."

        except Exception as e:
            result = -1
            report_message = f"An error occurred while checking for status bar or JavaScript patterns: {e}"

        # Store the report message
        FeatureExtraction.report[self.url] = report_message
        self.report_dict["20. StatusBarCust"] = report_message
        return result

    def DisableRightClick(self):
        report_message = ""
        result = 1  # Assume no suspicious patterns found initially

        def is_domain_resolvable(url):
            try:
                domain = urlparse(url).netloc
                socket.gethostbyname(domain)
                return True
            except socket.error:
                return False

        if not is_domain_resolvable(self.url):
            report_message = "Domain is not resolvable."
            result = -1
        else:
            try:
                # Check if 'disable' or 'rightclick' is in the URL
                if 'disable' in self.url or 'rightclick' in self.url:
                    result = -1
                    report_message = "The URL contains 'disable' or 'rightclick', which may indicate attempts to disable right-click functionality, a common tactic in phishing sites."
                # Check if disabling right-click is found in the HTML content
                elif self.response and re.findall(r"event.button ?== ?2", self.response.text):
                    result = -1
                    report_message = "The HTML content contains code to disable right-click functionality, which may indicate phishing intent."
                else:
                    report_message = "No suspicious patterns related to disabling right-click functionality found, which is expected for legitimate sites."

            except Exception as e:
                result = -1
                report_message = f"An error occurred while checking for right-click disabling patterns: {e}"

        # Store the report message
        FeatureExtraction.report[self.url] = report_message
        self.report_dict["21. DisableRightClick"] = report_message
        return result


    def UsingPopupWindow(self):
        report_message = ""
        result = 1  # Assume no suspicious patterns found initially

        try:
            # Check if 'open' or 'pop' is in the URL
            if 'open' in self.url or 'pop' in self.url:
                result = -1
                report_message = "The URL contains 'open' or 'pop', which may indicate the use of popup windows or new tabs, a common tactic in phishing sites."
            # Check if 'alert(' is present in the HTML content
            elif self.response and re.findall(r"alert\(", self.response.text):
                result = -1
                report_message = "The HTML content contains 'alert(', which may indicate the use of popup alerts, a common tactic in phishing sites."
            else:
                report_message = "No suspicious patterns related to popup windows or alerts found, which is expected for legitimate sites."

        except Exception as e:
            result = -1
            report_message = f"An error occurred while checking the URL and HTML content for popup window patterns: {e}"

        # Store the report message
        FeatureExtraction.report[self.url] = report_message
        self.report_dict["22. UsingPopupWindow"] = report_message
        return result

    def IframeRedirection(self):
        report_message = ""
        result = 1  # Assume no suspicious patterns found initially

        try:
            if self.response:
                if re.findall(r"<iframe|<frameBorder>", self.response.text, re.IGNORECASE):
                    result = -1
                    report_message = "The HTML content contains 'iframe' or 'frameBorder' tags, which may indicate potential iframe redirection."
                elif 'iframe' in self.url:
                    result = -1
                    report_message = "The URL contains 'iframe', which may indicate potential iframe redirection, a technique sometimes used in phishing."
                else:
                    report_message = "No suspicious patterns related to iframe redirection found, which is expected for legitimate sites."
            else:
                result = -1
                report_message = "No response from the server; unable to check for iframe redirection."

        except Exception as e:
            result = -1
            report_message = f"An error occurred while checking for iframe redirection: {e}"

        # Store the report message
        FeatureExtraction.report[self.url] = report_message
        self.report_dict["23. IframeRedirection"] = report_message
        return result

    def AgeofDomain(self):
        report_message = ""
        result = 1  # Assume the domain is sufficiently aged initially

        try:
            # Perform WHOIS lookup to get domain information
            domain_info = whois.whois(self.urlparse.netloc)
            creation_date = domain_info.creation_date
            today_date = date.today()

            # Handle cases where creation_date might be a list
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            # Calculate the age of the domain
            age_of_domain = today_date.year - creation_date.year - ((today_date.month, today_date.day) < (creation_date.month, creation_date.day))
            
            # Determine result based on domain age
            if age_of_domain >= 6:
                result = 1
                report_message = "The domain is sufficiently aged (6 years or older), which is expected for a legitimate site."
            else:
                result = -1
                report_message = "The domain is relatively new (less than 6 years old), which may be suspicious for a legitimate site."

        except Exception as e:
            result = -1
            report_message = f"An error occurred while checking the domain age: {e}"

        # Store the report message
        FeatureExtraction.report[self.url] = report_message
        self.report_dict["24. AgeofDomain"] = report_message
        return result

    def DNSRecording(self):
        try:
            domain = whois.whois(self.url)
            if not domain.name_servers:
                return -1
            else:
                return 1
        except:
            return -1

    # def WebsiteTraffic(self):
    #     try:
    #         search_keyword = self.url
    #         for j in search(search_keyword, num=10, stop=10, pause=2):
    #             return -1
    #         return 1
    #     except:
    #         return -1

    # def PageRank(self):
    #     try:
    #         url = "http://data.alexa.com/data?cli=10&dat=s&url=" + self.url
    #         xml = urllib.request.urlopen(url)
    #         dom = BeautifulSoup(xml, "html.parser")
    #         rank = int(dom.find("REACH")["RANK"])
    #         if rank < 100000:
    #             return 1
    #         else:
    #             return -1
    #     except Exception as e:  # You should ideally capture specific exceptions
    #         print(f"An error occurred when checking PageRank: {e}")
    #         return -1  # or return 0, if that's more appropriate for indicating an 'unknown' state

    def GoogleIndex(self):
        report_message = ""
        result = -1  # Default to -1 if the URL is not found in the top 10 results

        def normalize_url(url):
            """Normalize the URL by removing schema and www prefixes."""
            parsed_url = urlparse(url)
            return urlunparse(('', '', parsed_url.path, parsed_url.params, parsed_url.query, parsed_url.fragment)).lower()

        try:
            # Perform the Google search (ensure user-agent to avoid blocking)
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
            search_url = f"https://www.google.com/search?q={self.url}"
            response = requests.get(search_url, headers=headers)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find all <a> tags in the search results
            a_tags = soup.find_all('a', limit=30)  # Limit to top 10 results

            # Debugging: Print href attribute content
            for i, a in enumerate(a_tags):
                href = a.get('href')
                #if href:
                   #print(f"A {i}: {href}")

            # Normalize the URL to match
            normalized_url = normalize_url(self.url)

            # Check if the URL appears in the first 5 <a> tags
            for index, a in enumerate(a_tags[15:20]):
                href = a.get('href')
                if href:
                    # Extract URL from href attribute
                    extracted_url = urlparse(href).netloc
                    if normalize_url(extracted_url) == normalized_url:
                        result = 1  # URL is in the top 5 results
                        report_message = "The website is in the top 5 Google search results (within <a> tags), indicating high relevance."
                        break
            else:
                # Check if URL is in the top 10 results
                for index, a in enumerate(a_tags[20:30]):
                    href = a.get('href')
                    if href:
                        # Extract URL from href attribute
                        extracted_url = urlparse(href).netloc
                        if normalize_url(extracted_url) == normalized_url:
                            result = 0  # URL is in the top 10 results but not in the top 5
                            report_message = "The website is in the top 10 Google search results (within <a> tags) but not in the top 5, indicating moderate relevance."
                            break
                else:
                    # URL not found in the top 10 results
                    report_message = "The website is not in the top 10 Google search results (within <a> tags), indicating lower relevance."

        except Exception as e:
            result = -1
            report_message = f"An error occurred while checking Google indexing status: {e}"

        # Store the report message
        FeatureExtraction.report[self.url] = report_message
        self.report_dict["26. GoogleIndex"] = report_message
        return result


    def LinksPointingToPage(self):
        report_message = ""
        result = -1  # Assume a negative result initially

        try:
            # Count the number of links on the page
            number_of_links = len(re.findall(r"<a href=", self.response.text))

            # Determine the result based on the number of links
            if number_of_links == 0:
                result = -1  # No links found, which is expected for some legitimate pages
                report_message = "The page has no links pointing to it, which is unusual for legitimate websites and could be indicative of a phishing attempt."
            elif number_of_links <= 2:
                result = 0  # Fewer links might indicate a less trustworthy or less connected page
                report_message = f"The page has {number_of_links} link(s), which is typically characteristic of phishing sites aiming to appear legitimate with minimal content."
            else:
                result = 1  # Excessive number of links might be indicative of certain suspicious behaviors
                report_message = f"The page has {number_of_links} link(s), suggesting it is a well-connected, legitimate site with extensive content and resources."

        except Exception as e:
            result = -1
            report_message = f"An error occurred while checking the number of links pointing to the page: {e}. This could be due to the site structure or an intentional attempt to obfuscate content."

        # Store the report message
        FeatureExtraction.report[self.url] = report_message
        self.report_dict["27. LinksPointingToPage"] = report_message
        return result

    def StatsReport(self):
        result = 1  # Assume the URL is not suspicious initially
        report_message = ""

        try:
            # Check URL match against known patterns
            url_match = re.search(
                r'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly',
                self.url
            )

            # Resolve IP address of the domain
            ip_address = socket.gethostbyname(self.urlparse.netloc)
            ip_match = re.search(
                r'146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                r'107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                r'118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                r'216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                r'34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                r'216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',
                ip_address
            )

            # Determine result and report message based on matches
            if url_match or ip_match:
                result = -1
                report_message = "The URL or IP matches known suspicious patterns."
            else:
                report_message = "The URL and IP do not match any known suspicious patterns."

        except Exception as e:
            result = -1
            report_message = f"An error occurred while performing the stats check: {e}"

       # Store the report message
        FeatureExtraction.report[self.url] = report_message
        self.report_dict["28. StatsReport"] = report_message
        return result
    


    def getFeaturesList(self):
        return self.features

    def write_report(self, filename="report.txt"):
        # Define the folder name
        folder_name = "static/report"
        
        def sanitize_filename(filename):
        # Remove characters not allowed in filenames
            nm = re.sub(r'[<>:"/\\|?*\t]', '', filename)
            name = nm+".txt"
            return name
        # Ensure the folder exists
        if not os.path.exists(folder_name):
            os.makedirs(folder_name)
        
        # Sanitize the filename
        filename = sanitize_filename(filename)
        print(filename)
        # Construct the full path
        file_path = os.path.join(folder_name, filename)
        print(file_path)
        # Write the report to the file
        with open(file_path, "w") as f:
            for feature, message in self.report_dict.items():
                f.write(f"{feature}: {message}\n")
        return filename
    

# Example usage:
if __name__ == "__main__":
    test_urls = [
    "https://www.google.com", 
    # "http://drop-box-roug9779888876n1a2b3c4d5e6f7g8h9i0jk1l2m3n4o5p6q7r8s9t.vercel.app/	",
    # "https://github.com/",  # Replace with an actual website for a real test
    ]
    for url in test_urls:
           
        print(url)
        fe = FeatureExtraction(url)
        features = fe.getFeaturesList()
        print(features)
        fe.write_report()
        features.clear()
        

# Optionally, if you want to print the entire report.

# print("Final Report:")
# for url, result in FeatureExtraction.report.items():
#     print(f"{url}: {result}")
