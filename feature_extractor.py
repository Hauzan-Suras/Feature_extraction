import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
import whois
from datetime import datetime, timezone
import csv
import pandas as pd
import tldextract
from urllib.parse import urljoin, urlparse, parse_qs
import ssl
import time
import certifi
import urllib3
from urllib3.exceptions import InsecureRequestWarning
import dns.resolver
import signal
from functools import wraps
import errno
import os

# Combine all feature names
feature_names = [
    "Having_IP_Address",
    "URL_Length",
    "Shortining_Service",
    "Double_slash_redirecting",
    "Prefix_Suffix",
    "Having_Sub_Domain",
    "SSLfinal_State",
    "Suspicious_parameter", 
    "Favicon",
    "HTTPS_token",
    "Request_URL",
    "URL_of_Anchor",
    "Links_in_tags",
    "SFH",
    "Submitting_to_email",
    "Abnormal_URL",
    "Redirect",
    "on_mouseover",
    "RightClick",
    "popUpWindow",
    "Iframe",
    "Age_of_domain",
    "DNSRecord",
    "Web_traffic",
    "Links_pointing_to_page",
    "Statistical_report"    
]

def timeout(seconds=300):
    def decorator(func):
        def wrapper(*args, **kwargs):
            import threading
            import queue
            
            result_queue = queue.Queue()
            error_queue = queue.Queue()
            
            def worker():
                try:
                    result = func(*args, **kwargs)
                    result_queue.put(result)
                except Exception as e:
                    error_queue.put(e)
            
            thread = threading.Thread(target=worker)
            thread.daemon = True
            
            thread.start()
            thread.join(timeout=seconds)
            
            if thread.is_alive():
                raise TimeoutError(f"Processing timed out after {seconds} seconds")
            
            if not error_queue.empty():
                raise error_queue.get()
            
            if not result_queue.empty():
                return result_queue.get()
            
            raise Exception("Unknown error occurred during processing")
            
        return wrapper
    return decorator

@timeout(180)  # 3 minutes timeout
def process_url_with_timeout(url, label, max_retries=2):
    """Process a URL with timeout handling"""
    return process_url(url, label, max_retries)

def is_ip_address(url):
    url = re.sub(r'^https?://', '', url)
    domain = url.split('/')[0]
    domain = domain.split(':')[0]
    if not re.match(r'^[\d.]+$', domain):
        return False
    octets = domain.split('.')
    if len(octets) != 4:
        return False
    for octet in octets:
        if not octet.isdigit() or int(octet) < 0 or int(octet) > 255:
            return False
    return True

def check_ssl_final_state(url):
    try:
        hostname = url.split("://")[-1].split("/")[0]
        context = ssl.create_default_context()
        if is_ip_address(hostname):
            context.check_hostname = False
            
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=None if is_ip_address(hostname) else hostname) as secure_sock:
                cert = secure_sock.getpeercert()
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                not_after = not_after.replace(tzinfo=timezone.utc)
                return 1 if not_after > datetime.now(timezone.utc) else 0
    except (ssl.SSLError, socket.timeout, ConnectionRefusedError) as e:
        print(f"SSL Error for {url}: {str(e)}")
        return -1
    except Exception as e:
        print(f"Error checking SSL for {url}: {str(e)}")
        return -1

def check_shortening_service(domain):
    domain_parts = domain.split('.')
    base_domain = '.'.join(domain_parts[-2:]) if len(domain_parts) >= 2 else domain
    
    shortening_services = {
        'bit.ly', 't.co', 'lnkd.in', 'tinyurl.com', 'ow.ly', 'wp.me', 'adf.ly', 'bitly.com'
    }
    return -1 if base_domain in shortening_services else 1

def check_suspicious_parameters(url):
    """Check for suspicious parameters in the URL"""
    try:
        # Parse the URL and get query parameters
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # List of suspicious parameter patterns
        suspicious_params = [
            'start', 'delay', 'redirect', 'return', 'return_to', 'returnto',
            'return_url', 'returnurl', 'return_path', 'returnpath',
            'delayms', 'delay_ms', 'loop', 'goto', 'next', 'redir',
            'redirect_uri', 'redirect_url', 'success', 'error'
        ]
        
        # Check if any suspicious parameters exist
        for param in suspicious_params:
            if param in query_params:
                return -1
        
        return 1
        
    except Exception as e:
        print(f"Error checking suspicious parameters for {url}: {str(e)}")
        return -1

def check_email_submission(soup, response_text):
    """
    Improved email submission check that looks for:
    1. mailto: links
    2. email input fields
    3. forms that submit to mail handlers
    """
    if soup is None or response_text is None:
        return -1
    
    # Check for mailto: links
    mailto_links = soup.find_all(href=re.compile(r"mailto:", re.I))
    
    # Check for email input fields
    email_inputs = soup.find_all('input', {'type': 'email'})
    email_inputs.extend(soup.find_all('input', {'name': re.compile(r'email|mail', re.I)}))
    
    # Check form actions for mail-related endpoints
    forms = soup.find_all('form')
    mail_forms = [form for form in forms if form.get('action', '').lower().find('mail') != -1]
    
    # Check for other email-related patterns in the page
    email_patterns = [
        r'[^@\s]+@[^@\s]+\.[^@\s]+',  # Basic email pattern
        r'mail\s*\(',                   # mail() function calls
        r'email=',                      # email parameters
        r'sendmail'                     # sendmail references
    ]
    
    has_email_patterns = any(re.search(pattern, response_text, re.I) for pattern in email_patterns)
    
    # Return 1 if no email-related elements are found, -1 if any are found
    if not (mailto_links or email_inputs or mail_forms or has_email_patterns):
        return 1
    return -1

def check_abnormal_url(url, response):
    """
    Improved abnormal URL detection that checks for:
    1. Unusual port numbers
    2. IP addresses instead of domain names
    3. Unusual characters in hostname
    4. Mismatch between displayed and actual URLs
    5. Presence of multiple subdomains
    """
    if response is None:
        return -1
        
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc
    
    # Check for IP address in hostname
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(ip_pattern, hostname.split(':')[0]):
        return -1
        
    # Check for unusual port
    if ':' in hostname and parsed_url.port not in [80, 443]:
        return -1
        
    # Check for excessive subdomains
    subdomain_count = len(hostname.split('.')) - 2
    if subdomain_count > 3:
        return -1
        
    # Check for unusual characters
    unusual_chars = re.findall(r'[^a-zA-Z0-9.-]', hostname)
    if unusual_chars:
        return -1
        
    # Check final URL after redirects
    if response.url != url and not url.startswith(response.url):
        return -1
        
    return 1

def check_redirect(response):
    """
    Improved redirect checker that considers:
    1. Number of redirects
    2. Types of redirects
    3. Cross-domain redirects
    """
    if response is None or not hasattr(response, 'history'):
        return -1
        
    redirect_count = len(response.history)
    
    if redirect_count == 0:
        return 1
        
    # Get all domains involved in redirect chain
    domains = set()
    if response.history:
        domains.add(urlparse(response.history[0].url).netloc)
        for resp in response.history:
            domains.add(urlparse(resp.url).netloc)
        domains.add(urlparse(response.url).netloc)
    
    # Check if redirects cross domains
    cross_domain = len(domains) > 1
    
    # Classify based on number of redirects and whether they cross domains
    if redirect_count > 4:
        return -1
    elif redirect_count > 2 and cross_domain:
        return -1
    elif redirect_count > 1:
        return 0
    return 1

def check_mouseover(soup, response_text):
    """
    Improved mouseover detection that checks for:
    1. onmouseover events in script tags
    2. inline onmouseover attributes
    3. Event listeners for mouseover
    4. Status bar manipulation
    """
    if soup is None or response_text is None:
        return -1
        
    # Check for script tags containing onmouseover
    script_mouseover = bool(re.search(r'<script[^>]*>.*onmouseover.*</script>', response_text, re.I | re.S))
    
    # Check for inline onmouseover attributes
    inline_mouseover = bool(soup.find_all(attrs={'onmouseover': True}))
    
    # Check for addEventListener('mouseover')
    event_listener = 'addEventListener' in response_text and 'mouseover' in response_text
    
    # Check for status bar manipulation
    status_bar = bool(re.search(r'window\.status|document\.location', response_text, re.I))
    
    if script_mouseover or inline_mouseover or (event_listener and status_bar):
        return -1
    return 1

def create_secure_session():
    """
    Creates a requests session with proper SSL/TLS configuration
    """
    session = requests.Session()
    session.verify = certifi.where()
    
    adapter = requests.adapters.HTTPAdapter(
        max_retries=3,
        pool_connections=10,
        pool_maxsize=10
    )
    
    session.mount('https://', adapter)
    session.mount('http://', adapter)
    
    return session

def fetch_url(url, allow_insecure=True):
    """
    Fetches URL content with proper SSL/TLS handling
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    session = create_secure_session()
    
    try:
        # First try with verification
        response = session.get(url, headers=headers, timeout=10)
        return response
        
    except requests.exceptions.SSLError as e:
        if not allow_insecure:
            return None, f"SSL verification failed: {str(e)}"
            
        # If allowed, try again without verification
        urllib3.disable_warnings(InsecureRequestWarning)
        try:
            response = session.get(
                url,
                headers=headers,
                verify=False,
                timeout=10
            )
            return response
        except requests.exceptions.RequestException as e:
            return None, f"Failed even with SSL verification disabled: {str(e)}"
            
    except requests.exceptions.Timeout:
        return None, "Request timed out"
    except requests.exceptions.ConnectionError:
        return None, "Failed to connect to server"
    except requests.exceptions.TooManyRedirects:
        return None, "Too many redirects"
    except requests.exceptions.RequestException as e:
        return None, f"Request failed: {str(e)}"

def process_url(url, label, max_retries=2):
    """
    Process a URL with multiple retry attempts and error handling
    """
    errors = []
    
    for attempt in range(max_retries):
        try:
            response = fetch_url(url)
            if isinstance(response, tuple):  # Error occurred
                errors.append(f"Attempt {attempt + 1}: {response[1]}")
                continue
                
            features = generate_data_set(url, response)
            if features is not None:
                return features, None
                
            errors.append(f"Attempt {attempt + 1}: Feature extraction failed")
            time.sleep(1)
            
        except Exception as e:
            errors.append(f"Attempt {attempt + 1}: {str(e)}")
            time.sleep(1)
            
    return None, "; ".join(errors)

def analyze_links(soup, domain):
    """
    Analyzes links on the page for various security indicators
    Returns 1 if suspicious, 0 if neutral, -1 if likely safe
    """
    if soup == -999:
        return -1
        
    try:
        # Get all links
        links = soup.find_all('a', href=True)
        
        if not links:
            return 1  # Suspicious if no links at all
            
        # Initialize counters
        external_links = 0
        internal_links = 0
        suspicious_links = 0
        
        for link in links:
            href = link.get('href', '').lower()
            
            # Skip empty or javascript links
            if not href or href.startswith('javascript:'):
                continue
                
            # Check if link is internal or external
            if domain.lower() in href or href.startswith('/'):
                internal_links += 1
            else:
                external_links += 1
                
            # Check for suspicious patterns
            suspicious_patterns = [
                'login', 'signin', 'account', 'password', 'secure',
                '.php?', 'redirect', 'click.php', 'verify'
            ]
            if any(pattern in href for pattern in suspicious_patterns):
                suspicious_links += 1
        
        total_links = internal_links + external_links
        
        # Analysis logic
        if total_links == 0:
            return 1  # Suspicious - no valid links
        elif suspicious_links > total_links * 0.3:
            return 1  # Suspicious - high proportion of suspicious links
        elif external_links > internal_links * 3:
            return 0  # Neutral - unusually high external links
        elif internal_links > 0 and external_links > 0:
            return -1  # Likely safe - balanced mix of internal/external links
        else:
            return 0  # Neutral - other cases
            
    except Exception as e:
        print(f"Error in link analysis: {str(e)}")
        return -1

def is_suspicious_brand_url(url, domain):
    """
    Detect sophisticated brand impersonation in URLs
    """
    common_brands = {}
    legitimate_cctlds = [
    # Basic ccTLDs
    '.ca', '.fr', '.de', '.it', '.es', '.nl', '.se', '.no', 
    '.dk', '.ch', '.ie',

    # Common SLD + ccTLD combinations
    '.co.uk',    # United Kingdom
    '.co.jp',    # Japan 
    '.co.kr',    # South Korea
    '.com.sg',   # Singapore
    '.com.au',   # Australia
    '.co.nz',    # New Zealand
    '.co.za',    # South Africa
    '.co.id',    # Indonesia
    '.com.br',   # Brazil
    '.com.mx',   # Mexico
    '.co.th',    # Thailand
    '.co.in',    # India
    '.com.hk',   # Hong Kong
    '.com.tw',   # Taiwan
    '.co.il',    # Israel
    '.com.my',   # Malaysia
    '.com.ar',   # Argentina
    '.com.ph',   # Philippines
    '.com.tr',   # Turkey
    '.co.ve',    # Venezuela
    '.com.ua',   # Ukraine
    '.co.ae',    # UAE
    ]
    
    # Generate brand domains with ccTLDs
    base_brands = {
        'paypal': 'paypal',
        'google': 'google',
        'facebook': 'facebook',
        'amazon': 'amazon',
        'apple': 'apple',
        'microsoft': 'microsoft'
    }
    
    for brand, base in base_brands.items():
        common_brands[brand] = [f"{base}.com"]  # Add main .com domain
        common_brands[brand].extend([f"{base}{tld}" for tld in legitimate_cctlds])
        # Add special case for UK's .co.uk
        if brand in ['paypal', 'google', 'amazon']:
            common_brands[brand].append(f"{base}.co.uk")
    
    url_lower = url.lower()
    domain_lower = domain.lower()
    
    for brand, legit_domains in common_brands.items():
        brand_not_primary = all(brand_domain not in domain_lower for brand_domain in legit_domains)
        
        checks = [
            any(f'/{legit_domain}/' in url_lower for legit_domain in legit_domains),
            any(re.search(fr'{re.escape(legit_domain)}\..*\.[a-z]+/', url_lower) for legit_domain in legit_domains),
            (brand in url_lower and brand_not_primary and 
             any(suspicious_path in url_lower for suspicious_path in 
                 ['login', 'signin', 'verify', 'account', 'webscr', 'cgi-bin'])),
            (brand in url_lower and brand_not_primary and 
             any(ext in url_lower for ext in ['.html', '.php', '.htm', '.aspx']) and
             '/' in url_lower)
        ]
        
        if any(checks):
            return True
    
    return False

def statistical_report(domain, url, soup):
    """
    Enhanced statistical analysis of the website with improved ccTLD support
    Returns 1 if likely safe, 0 if neutral, -1 if suspicious
    """
    try:
        score = 0
        print("\nDetailed Statistical Analysis:")
        print("-" * 30)
        
        # 1. Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.work', '.date', '.bid']
        legitimate_tlds = ['.com', '.org', '.edu', '.gov', '.net', '.io', '.business']
        
        # List of legitimate ccTLDs (add more as needed)
        legitimate_cctlds = [
            '.ca',  # Canada
            '.uk',  # United Kingdom
            '.au',  # Australia
            '.nz',  # New Zealand
            '.fr',  # France
            '.de',  # Germany
            '.it',  # Italy
            '.es',  # Spain
            '.jp',  # Japan
            '.kr',  # South Korea
            '.cn',  # China
            '.in',  # India
            '.br',  # Brazil
            '.mx',  # Mexico
            '.ru',  # Russia
            '.nl',  # Netherlands
            '.se',  # Sweden
            '.no',  # Norway
            '.dk',  # Denmark
            '.ch',  # Switzerland
            '.ie',  # Ireland
            '.sg',  # Singapore
        ]
        
        tld_score = 0
        domain_lower = domain.lower()
        
        # Check for suspicious TLDs
        if any(domain_lower.endswith(tld) for tld in suspicious_tlds):
            tld_score = -1
        # Check for legitimate TLDs or ccTLDs
        elif any(domain_lower.endswith(tld) for tld in legitimate_tlds + legitimate_cctlds):
            tld_score = 1
        # Handle multi-part ccTLDs (e.g., .co.uk, .com.au)
        elif any(re.search(fr'\.(?:co|com|org|edu|gov|ac)\.[a-z]{{2}}$', domain_lower)):
            tld_score = 1
            
        score += tld_score
        print(f"1. TLD legitimacy check: {tld_score}")
            
        # 2. Check domain length
        length_score = 0
        if len(domain) > 40:
            length_score = -1
            score += length_score
        print(f"2. Domain length check: {length_score}")
        
        # 3. Check for character composition
        char_score = 0
        if soup != -999:
            # Calculate ratio of special characters
            special_chars = sum(1 for c in domain if not c.isalnum() and c not in ['.', '-'])
            if special_chars > 3:
                char_score -= 1
                score -= 1
            
            # Check for numeric character ratio
            num_count = sum(c.isdigit() for c in domain)
            if num_count / len(domain) > 0.3:
                char_score -= 1
                score -= 1
        print(f"3. Character composition check: {char_score}")
        
        # 4. Check for common legitimate domain patterns
        legit_score = 0
        # Enhanced pattern matching for subdomains
        subdomain_patterns = [
            r'^[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+\.[a-z]{2,}$',  # basic subdomain
            r'^(?:[a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-z]{2,}$',  # multiple subdomains
            r'^[a-zA-Z0-9-]+\.(?:com|org|edu|gov|net)\.[a-z]{2}$'  # country-specific commercial/organizational
        ]

        if any(re.match(pattern, domain_lower) for pattern in subdomain_patterns):
            legit_score = 1
            score += legit_score

        print(f"4. Legitimate domain pattern check: {legit_score}")
        
        # 5. Enhanced Brand Impersonation Check
        brand_score = 0
        if is_suspicious_brand_url(url, domain):
            brand_score = -2
            score += brand_score
        print(f"5. Brand impersonation check: {brand_score}")
        
        # 6. Check page content
        content_score = 0
        if soup != -999:
            # Check for secure connection on sensitive pages
            password_fields = soup.find_all('input', {'type': 'password'})
            payment_fields = soup.find_all('input', {'type': ['credit-card', 'card-number']})
            sensitive_keywords = ['login', 'signin', 'payment', 'checkout', 'account']
            
            has_sensitive_content = (
                password_fields or 
                payment_fields or 
                any(keyword in str(soup).lower() for keyword in sensitive_keywords)
            )
            
            if has_sensitive_content:
                if not url.startswith('https'):
                    content_score -= 2
                else:
                    content_score += 1
                    
            # Check for suspicious form submissions
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '').lower()
                if any(keyword in action for keyword in sensitive_keywords):
                    if not url.startswith('https'):
                        content_score -= 1
                    
            score += content_score
        print(f"6. Page content check: {content_score}")
        
        print(f"Final total score: {score}")
        print("-" * 30)
        
        # Adjusted scoring thresholds
        if score >= 2:
            return 1  # Likely safe
        elif score <= -2:
            return -1  # Suspicious
        else:
            return 0  # Neutral
            
    except Exception as e:
        print(f"Error in statistical analysis: {str(e)}")
        return -1

def age_of_domain(domain):
    try:
        w = whois.whois(domain)
        if isinstance(w.creation_date, list):
            creation_date = w.creation_date[0]
        else:
            creation_date = w.creation_date

        if creation_date:
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            current_date = datetime.now(timezone.utc)
            registration_length = (current_date - creation_date).days
            return 1 if registration_length > 365 else -1
        else:
            return -1
    except Exception as e:
        print(f"Error checking domain age for {domain}: {str(e)}")
        return -1

def extract_domain_info(url):
    """Extract domain information using tldextract"""
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    return domain

def check_https(url):
    """Check if the URL uses HTTPS"""
    return url.startswith('https://')

def generate_data_set(url, label):
    """
    Combined function to generate all features for phishing detection
    """
    data_set = []
    domain = ""
    DEFAULT_ERROR_VALUE = -1

    # Standardize URL format
    if not re.match(r"^https?", url):
        url = "http://" + url

    # Initialize response variables
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124'
        }
        
        # Get both initial and redirected responses
        initial_response = requests.get(url, timeout=10, allow_redirects=False, headers=headers, verify=False)
        final_response = requests.get(url, timeout=10, allow_redirects=True, headers=headers, verify=False)
        print(f"Final URL after redirects for {url}: {final_response.url}")
        
        soup = BeautifulSoup(final_response.text, 'html.parser')
        response = final_response  # For compatibility
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {str(e)}")
        initial_response = None
        final_response = None
        response = None
        soup = None

    # Extract domain
    domain_match = re.findall(r"://([^/]+)/?", url)
    if domain_match:
        domain = domain_match[0]
        if re.match(r"^www\.", domain):
            domain = domain.replace("www.", "")
    else:
        print(f"Domain extraction failed for {url}")
        domain = ""

    try:
        whois_response = whois.whois(domain)
    except:
        whois_response = None

    # 1. having_IP_Address
    data_set.append(-1 if is_ip_address(url) else 1)

    # 2. URL_Length
    data_set.append(1 if len(url) < 54 else 0 if len(url) <= 75 else -1)

    # 3. Shortining_Service
    data_set.append(check_shortening_service(domain))

    # 4. double_slash_redirecting
    list_slash = [x.start(0) for x in re.finditer('//', url)]
    expected_position = 7 if url.startswith('https') else 6
    data_set.append(-1 if list_slash and list_slash[-1] > expected_position else 1)

    # 5. Prefix_Suffix
    data_set.append(-1 if re.search(r"https?://[^\s/]+-[^\s/]+", url) else 1)

    # 6. having_Sub_Domain
    sub_domains = len(re.findall(r"\.", domain))
    data_set.append(1 if sub_domains == 1 else 0 if sub_domains == 2 else -1)

    # 7. SSLfinal_State
    data_set.append(check_ssl_final_state(url))

    # 8. suspicious_parameter 
    data_set.append(check_suspicious_parameters(url))

    # 9. Favicon
    if soup is None:
        data_set.append(-1)
    else:
        favicon_found = False
        try:
            for head in soup.find_all('head'):
                for link in head.find_all('link', rel=True, href=True):
                    rel = link['rel']
                    href = link['href']
                    if any("icon" in r.lower() for r in rel):
                        if href.startswith('data:'):
                            print(f"Skipping base64-encoded favicon for {url}")
                            continue
                        try:
                            favicon_url = urljoin(url, href)
                            favicon_response = requests.head(favicon_url, timeout=5, verify=False)
                            if favicon_response.status_code == 200:
                                favicon_found = True
                                break
                        except requests.exceptions.RequestException:
                            continue
                if favicon_found:
                    break
            if not favicon_found:
                try:
                    fallback_favicon = urljoin(url, '/favicon.ico')
                    favicon_response = requests.head(fallback_favicon, timeout=5, verify=False)
                    if favicon_response.status_code == 200:
                        favicon_found = True
                except requests.exceptions.RequestException:
                    pass
            data_set.append(1 if favicon_found else -1)
        except Exception as e:
            print(f"Error during favicon extraction for {url}: {str(e)}")
            data_set.append(-1)

    # Features 11-20 (HTML and Request)

    # 10. HTTPS_token
    if response is None:
        data_set.append(DEFAULT_ERROR_VALUE)
    else:
        initial_is_https = initial_response.url.startswith("https://")
        final_is_https = final_response.url.startswith("https://")
        data_set.append(1 if (initial_is_https or final_is_https) else -1)

    # 11. Request_URL
    if soup is None:
        data_set.append(DEFAULT_ERROR_VALUE)
    else:
        i = 0
        success = 0
        for tag in ['img', 'audio', 'embed', 'iframe', 'source', 'track', 'video']:
            for element in soup.find_all(tag, src=True):
                src = element['src'].lower()
                if src.startswith(('http://', 'https://')):
                    parsed_src = urlparse(src)
                    if domain in parsed_src.netloc:
                        success += 1
                elif src.startswith(('/', './', '../')):
                    success += 1
                i += 1
        try:
            percentage = success / float(i) * 100
            if percentage < 25.0:
                data_set.append(1)
            elif 25.0 <= percentage < 65.0:
                data_set.append(0)
            else:
                data_set.append(-1)
        except ZeroDivisionError:
            data_set.append(1)

    # 12. URL_of_Anchor
    if soup is None:
        data_set.append(DEFAULT_ERROR_VALUE)
    else:
        i = 0
        unsafe = 0
        for a in soup.find_all('a', href=True):
            href = a['href'].lower()
            suspicious_patterns = [
                '#', 'javascript:', 'mailto:', 'data:', 
                'file:', 'ftp:', 'tel:', 'sms:', 
                'whatsapp:', 'market:', 'intent:'
            ]
            if any(pattern in href for pattern in suspicious_patterns):
                unsafe += 2
            elif not (url in href or domain in href):
                if not href.startswith(('/', './', '../')):
                    unsafe += 1
            i += 1
        try:
            percentage = unsafe / float(i) * 100
            if percentage < 35.0:
                data_set.append(1)
            elif 35.0 <= percentage < 70.0:
                data_set.append(0)
            else:
                data_set.append(-1)
        except ZeroDivisionError:
            data_set.append(1)

    # 13. Links_in_tags
    if soup is None:
        data_set.append(DEFAULT_ERROR_VALUE)
    else:
        i = 0
        success = 0
        tag_attrs = {
            'link': ['href', 'src'],
            'script': ['src', 'href'],
            'meta': ['content'],
            'style': ['src']
        }
        for tag, attrs in tag_attrs.items():
            for element in soup.find_all(tag):
                for attr in attrs:
                    if element.get(attr):
                        i += 1
                        attr_value = element[attr].lower()
                        if (url in attr_value or domain in attr_value or 
                            attr_value.startswith(('/', './', '../'))):
                            success += 1
        try:
            percentage = success / float(i) * 100
            if percentage < 20.0:
                data_set.append(1)
            elif 20.0 <= percentage < 85.0:
                data_set.append(0)
            else:
                data_set.append(-1)
        except ZeroDivisionError:
            data_set.append(1)

    # 14. SFH
    if soup is None:
        data_set.append(DEFAULT_ERROR_VALUE)
    else:
        forms = soup.find_all('form', action=True)
        if len(forms) == 0:
            data_set.append(1)
        else:
            suspicious_score = 0
            for form in forms:
                action = form['action'].lower()
                if action == "" or action == "about:blank":
                    suspicious_score = -1
                    break
                elif not any(pattern in action for pattern in [url, domain, '/', './']):
                    parsed_action = urlparse(action)
                    if parsed_action.netloc and parsed_action.netloc != domain:
                        suspicious_score = -1
                        break
                    suspicious_score = max(suspicious_score, 0)
                else:
                    suspicious_score = max(suspicious_score, 1)
            data_set.append(suspicious_score)

    # 15. Submitting_to_email
    if response is None or soup is None:
        data_set.append(DEFAULT_ERROR_VALUE)
    else:
        data_set.append(check_email_submission(soup, response.text))

    # 16. Abnormal_URL
    if response is None:
        data_set.append(DEFAULT_ERROR_VALUE)
    else:
        data_set.append(check_abnormal_url(url, response))

    # 17. Redirect
    if response is None:
        data_set.append(DEFAULT_ERROR_VALUE)
    else:
        data_set.append(check_redirect(response))

    # 18. on_mouseover
    if response is None or soup is None:
        data_set.append(DEFAULT_ERROR_VALUE)
    else:
        data_set.append(check_mouseover(soup, response.text))

    # 19. RightClick
    if response is None or response == "":
        data_set.append(-1)
    else:
        if any(keyword in response.text.lower() for keyword in ['oncontextmenu', 'return false', 'disable right click']):
            if 'return false' in response.text:
                if 'oncontextmenu' in response.text or 'event.button' in response.text:
                    data_set.append(1)
                else:
                    data_set.append(-1)
            else:
                data_set.append(1)
        else:
            data_set.append(-1)

    # 20. PopUpWindow
    if response is None or response == "":
        data_set.append(-1)
    else:
        if any(keyword in response.text.lower() for keyword in ['alert(', 'confirm(', 'prompt(', 'window.open(', 'showmodaldialog(']):
            data_set.append(1)
        else:
            data_set.append(-1)

    # 21. Iframe
    if response is None or response == "":
        data_set.append(-1)
    else:
        if re.search(r'<\s*iframe\b', response.text, re.IGNORECASE):
            data_set.append(1)
        else:
            data_set.append(-1)

    # 22. age_of_domain
    if domain:
        data_set.append(age_of_domain(domain))
    else:
        data_set.append(-1)

    # 23. DNSRecord
    try:
        if whois_response and whois_response.domain_name is not None:
            data_set.append(1)
        else:
            data_set.append(-1)
    except:
        data_set.append(-1)

    # 24. web_traffic
    try:
        web_response = requests.get(f"https://{domain}", timeout=5, headers=headers)
        social_patterns = ['facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com']
        if web_response.status_code == 200 and any(pattern in web_response.text.lower() for pattern in social_patterns):
            data_set.append(1)
        else:
            data_set.append(0)
    except:
        data_set.append(-1)

    # 25. Links_pointing_to_page
    data_set.append(analyze_links(soup, domain))

    # 26. Statistical_report
    data_set.append(statistical_report(domain, url, soup))

    return data_set

def format_time_elapsed(start_time):
    """Format elapsed time into hours, minutes, and seconds"""
    elapsed_time = time.time() - start_time
    hours = int(elapsed_time // 3600)
    minutes = int((elapsed_time % 3600) // 60)
    seconds = int(elapsed_time % 60)
    return hours, minutes, seconds

def log_skipped_url(skipped_urls_file, url, label, error_type, error_details, processing_duration):
    """Log a skipped URL to the specified CSV file with error details"""
    try:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        with open(skipped_urls_file, 'a', newline='') as skip_f:
            skip_writer = csv.writer(skip_f)
            skip_writer.writerow([
                url,
                label,
                error_type,
                error_details,
                timestamp,
                f"{processing_duration:.2f} seconds"
            ])
    except Exception as e:
        print(f"\nWarning: Could not log skipped URL - {str(e)}")

def main():
    """Main function to run the phishing detection system"""
    print("Phishing Website Detection System")
    print("--------------------------------")
    
    while True:
        print("\nChoose an option:")
        print("1. Process a single URL")
        print("2. Process URLs from CSV file")
        print("3. Exit")
        
        choice = input("Enter your choice (1-3): ")
        
        if choice == '1':
            url = input("Enter the URL to analyze: ")
            try:
                features, error = process_url_with_timeout(url, "")
                if features:
                    print("\nFeature Analysis Results:")
                    for feature, value in zip(feature_names, features):
                        print(f"{feature}: {value}")
                else:
                    print(f"\nError processing URL: {error}")
            except Exception as e:
                print(f"\nError: {str(e)}")
                
        elif choice == '2':
            # Batch processing from CSV
            input_file = input("Enter input CSV file name (e.g., urls.csv): ")
            output_file = input("Enter output CSV file name (e.g., results.csv): ")
            skipped_urls_file = input_file.rsplit('.', 1)[0] + '_skipped.csv'
            
            # Initialize counters
            processed_count = 0
            skipped_count = 0
            timeout_count = 0
            
            try:
                # Start timing
                start_time = time.time()
                
                # Initialize files
                with open(skipped_urls_file, 'w', newline='') as skip_f:
                    skip_writer = csv.writer(skip_f)
                    skip_writer.writerow([
                        'URL', 
                        'Label', 
                        'Error Type', 
                        'Error Details', 
                        'Timestamp',
                        'Processing Duration'
                    ])
                
                with open(output_file, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(feature_names + ["Label"])
                
                # Count total URLs
                with open(input_file, 'r') as f:
                    total_rows = sum(1 for row in csv.reader(f)) - 1
                
                # Process URLs
                with open(input_file, 'r') as f:
                    reader = csv.reader(f)
                    next(reader)  # Skip header
                    
                    for row_num, row in enumerate(reader, 1):
                        try:
                            url, label = row
                            current_time = time.time()
                            
                            print(f"\rProcessing URL {row_num}/{total_rows}: {url}")
                            
                            url_start_time = time.time()
                            
                            try:
                                features, error = process_url_with_timeout(url, label)
                                processing_duration = time.time() - url_start_time
                                
                                if features is None:
                                    log_skipped_url(skipped_urls_file, url, label, 'Failed', 
                                                error or "Unknown error", processing_duration)
                                    skipped_count += 1
                                    continue
                                
                                if len(features) == len(feature_names):
                                    features.append(label)
                                    with open(output_file, 'a', newline='') as output_f:
                                        writer = csv.writer(output_f)
                                        writer.writerow(features)
                                    processed_count += 1
                                else:
                                    log_skipped_url(skipped_urls_file, url, label, 'Incomplete',
                                                f"Got {len(features)} features, expected {len(feature_names)}", 
                                                processing_duration)
                                    skipped_count += 1
                                
                            except TimeoutError:
                                processing_duration = time.time() - url_start_time
                                log_skipped_url(skipped_urls_file, url, label, 'Timeout',
                                            'Processing exceeded 3 minutes', processing_duration)
                                timeout_count += 1
                                skipped_count += 1
                                continue
                                
                        except Exception as e:
                            print(f"\nError processing row {row_num}: {str(e)}")
                            continue
                            
                        # Add delay between requests
                        time.sleep(2)
                
                # Print final summary
                print("\nProcessing Summary:")
                print("=" * 50)
                print(f"Total URLs: {total_rows}")
                print(f"Successfully processed: {processed_count}")
                print(f"Skipped: {skipped_count}")
                print(f"  - Timeouts: {timeout_count}")
                print(f"  - Other errors: {skipped_count - timeout_count}")
                print(f"Results saved in: {output_file}")
                print(f"Skipped URLs logged in: {skipped_urls_file}")
                
            except Exception as e:
                print(f"\nFatal error: {str(e)}")
            
        elif choice == '3':
            print("Exiting program...")
            break
            
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()