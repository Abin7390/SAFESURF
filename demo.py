import whois
from datetime import date
from urllib.parse import urlparse

class FeatureExtraction:
    report = {}  # Class-level dictionary to store reports

class DomainChecker(FeatureExtraction):
    def __init__(self, url):
        self.url = url
        self.urlparse = urlparse(url)
        self.report_dict = {}

    def AgeofDomain(self):
        report_message = ""
        result = 1  # Assume the domain is sufficiently aged initially

        try:
            # Check if self.urlparse has been initialized correctly
            if not hasattr(self, 'urlparse') or not self.urlparse.netloc:
                raise ValueError("Invalid URL or URL parsing failed.")

            # Perform WHOIS lookup to get domain information
            domain_info = whois.whois(self.urlparse.netloc)
            creation_date = domain_info.creation_date
            today_date = date.today()

            # Handle cases where creation_date might be None or a list
            if creation_date is None:
                raise ValueError("Creation date not found in WHOIS data.")
            if isinstance(creation_date, list):
                creation_date = creation_date[0]  # Use the first date in the list

            # Check if creation_date is a valid date object
            if not isinstance(creation_date, date):
                raise ValueError("Invalid creation date format.")

            # Calculate the age of the domain
            age_of_domain = today_date.year - creation_date.year - (
                (today_date.month, today_date.day) < (creation_date.month, creation_date.day)
            )

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

# Demo to check the AgeofDomain function
if __name__ == "__main__":
    url_to_check = "https://www.google.com"  # Example URL
    checker = DomainChecker(url_to_check)
    result = checker.AgeofDomain()
    
    # Print results
    print(f"Result: {result}")
    print(f"Report: {checker.report_dict['24. AgeofDomain']}")
