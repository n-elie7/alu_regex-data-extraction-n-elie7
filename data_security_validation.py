"""
Data Extraction & Secure Validation System

This program extracts structured data from raw text using regex patterns
while implementing security measures to prevent malicious input from
compromising the system and avoiding exposing sensitive data in logs or any output streams.

I'm using Object Oriented Programming style to keep things organized.

N.B: This thing is battle tested use different test inputs as you want.
"""

import re

class SecureDataValidationExtractor:
    """
    A secure data extraction system that uses regex to identify and validate
    structured data patterns while defending against malicious input.

    N.B: I have extended the project to also catch things like 
    for example SQL injection patterns, XSS patterns, and also pattern traversal pattern
    which are also one of the most malicious techniques you don't want your system to face.
    """

    def __init__(self):
        """Initialize the extractor with regex patterns and additonal security filters."""

        # Matches standard email formats: username@domain.extension
        # like in project example emails to match (user@example.com, firstname.lastname@company.co.uk)
        # It Supports dots, hyphens, underscores in username and multiple domain levels

        # Additionally I have added security layer to mimic real production systems with security in mind
        # Security: Prevents SQL injection attempts and script tags
        self.email_pattern = re.compile(
            r"\b[a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]@[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}\b"
        )

        # Matches http/https urls with optional subdomains, paths, and query strings
        # There is also security layer that blocks cross site scripting and path traversal from urls
        # Security: Blocks javascript:, data:, and file: schemes
        self.url_pattern = re.compile(
            r"https?://(?:www\.)?[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}(?:/[^\s]*)?"
        )

        # It matches different phone number formats: (123) 456-7890, 123-456-7890, 123.456.7890 and other valid ones
        # It also supports international format with + prefix
        # Also this has security layer that prevents SQL injection like popular one eg: 'OR 1=1'
        # Which is always true to prevent your system to return sensitive data
        # Security: Rejects phone numbers with SQL injection attempts
        self.phone_number_pattern = re.compile(
            r"(?:\+\d{1,3}[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}\b"
        )

        # It matches common card formats as in project example: 1234-5678-9012-3456 or 1234 5678 9012 3456
        # It supports 13-19 digit cards (Visa, Mastercard, Amex, Discover)
        # Security: Validates using Luhn algorithm check if its valid one or randomly created by bad actor
        self.credit_card_pattern = re.compile(
            r"\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{4}[-\s]?\d{6}[-\s]?\d{5}\b"
        )

        # It matches both 12-hour (2:30 PM) and 24-hour (14:30) formats
        # Validates hours (0-23 or 1-12) and minutes (0-59)
        self.time_pattern = re.compile(
            r"\b(?:[01]?\d|2[0-3]):[0-5]\d(?:\s?(?:AM|PM|am|pm))?\b"
        )

        # It matches HTML tags with optional attributes: <tag>, <tag attr="value">
        # Security: Used to DETECT and SANITIZE potential XSS attacks
        self.html_tag_pattern = re.compile(
            r'<[a-zA-Z][a-zA-Z0-9]*(?:\s+[a-zA-Z][a-zA-Z0-9-]*(?:\s*=\s*(?:"[^"]*"|\'[^\']*\'|[^\s>]+))?)*\s*/?>'
        )

        # It matches social media hashtags: #Example, #ThisIsAHashtag
        # It must contain at least one letter (not just numbers)
        # Security: Prevents script injection via hashtags.
        self.hashtag_pattern = re.compile(r"#[a-zA-Z][a-zA-Z0-9_]*\b")

        # It matches dollar amounts: $19.99, $1,234.56
        # It supports optional commas for thousands separators
        # It validates proper decimal format (exactly 2 decimal places or none)
        self.currency_amount_pattern = re.compile(r"\$\d{1,3}(?:,\d{3})*(?:\.\d{2})?\b")


        # Since this is project is for Security Validation
        # as Junior Frontend Developer I choose to add other security layer as you have seen
        # from the top in order to stand out.
        # I have added SQL injection, XSS checking, and Path traversal checking.


        # This match any common SQL Injection patterns
        # It matches either in upper or lower case as i had to ignore the case.
        # It catches SQL comments or syntax of its
        self.sql_injection_pattern = re.compile(
            r"(?:--|;|'|\"|\bOR\b|\bAND\b|\bDROP\b|\bDELETE\b|\bINSERT\b|\bUPDATE\b|\bSELECT\b).*(?:TABLE|FROM|WHERE)",
            re.IGNORECASE,
        )

        # XSS patterns
        # This will help the system the system to catch malicious script
        # That can led to execution of javascript scripts in the user browser or any other clients he/she is using 
        self.xss_pattern = re.compile(
            r"<script|javascript:|onerror=|onload=|onclick=|<iframe|eval\(|document\.|window\.",
            re.IGNORECASE,
        )

        # Path traversal patterns
        # This will help the system to catch malcious inputs that's trying to traverse path,
        # And wants to gain unathorized access to some file and information so that system can
        # find a way to stop it from happening. 
        self.path_traversal_pattern = re.compile(
            r"\.\./|\.\.\\|/etc/passwd|/etc/shadow"
        )

    def is_input_safe(self, text: str) -> bool:
        """
        Security validation: Check if input contains malicious patterns.

        Args:
            text: Input string to validate

        Returns:
            True if input appears safe, False if malicious patterns detected
        """

        # This will be called to other methods to check first 
        # if there is not harmful scripts in it 
        # before continuing with normal regex check to enhance security.

        if self.sql_injection_pattern.search(text):
            return False
        elif self.xss_pattern.search(text):
            return False
        elif self.path_traversal_pattern.search(text):
            return False
        else:
            return True

    def sanitize_for_logging(self, text: str, data_type: str) -> str:
        """
        Sanitize sensitive data for safe logging.

        Args:
            text: Original text containing sensitive data
            data_type: Type of sensitive data (e.g., 'credit_card', 'email')

        Returns:
            Safe version to prevent exposing sensitive info in logs and outputs.
        """

        # Prevents sensitive data exposure in logs
        if data_type == "credit_card":
            # Mask all but not last 4 digits example 1234-5678-9012-3456 -> ****-****-****-3456
            return re.sub(r"\d", "*", text[:-4]) + text[-4:]
        elif data_type == "email":
            # Partial masking: user@domain.com -> u***@domain.com
            parts = text.split("@")
            if len(parts) == 2:
                username = (
                    parts[0][0] + "*" * (len(parts[0]) - 1)
                    if len(parts[0]) > 1
                    else parts[0]
                )
                return f"{username}@{parts[1]}"
        else:
            return text
        
    def validate_email(self, email: str) -> bool:
        """
        Additional validation for email addresses beyond regex.

        Args:
            email: Email address to validate

        Returns:
            True if email passes all validation checks
        """

        # here i checked if email is available 
        # or not longer than 254 based on rules.
        if not email or len(email) > 254:
            return False

        # Check for malicious patterns security layer
        # for checking SQL injections, XSS, and Path traversal.
        if not self.is_safe_input(email):
            return False

        # Split and validate parts
        # to avoid complexity to validate the whole thing at once.
        parts = email.split("@")
        if len(parts) != 2:
            return False

        username, domain = parts

        # Username validation
        if len(username) == 0 or len(username) > 64:
            return False
        if username.startswith(".") or username.endswith("."):
            return False
        if ".." in username:
            return False

        # Domain validation
        if len(domain) == 0 or len(domain) > 255:
            return False
        if domain.startswith(".") or domain.endswith("."):
            return False
        if ".." in domain:
            return False

        return True

    def validate_url(self, url: str) -> bool:
        """
        Additional validation for URLs beyond regex.

        Args:
            url: URL to validate

        Returns:
            True if URL passes all validation checks
        """

        # here i checked if url is available 
        # or not longer than 2048.
        # reasonable URL length limit
        if not url or len(url) > 2048:
            return False

        # Block malicious protocols
        # that can cause security issues
        # not all of them included but common ones 
        malicious_protocols = ["javascript:", "data:", "file:", "vbscript:"]
        if any(url.lower().startswith(protocol) for protocol in malicious_protocols):
            return False

        # Check for malicious attempts in URL
        # check the implementation of is_safe_input method above
        if not self.is_safe_input(url):
            return False

        return True

    def validate_phone_number(self, phone: str) -> bool:
        """
        Additional validation for phone numbers.

        Args:
            phone: Phone number to validate

        Returns:
            True if phone number is valid
        """

        # This checks if phone is not empty
        if not phone:
            return False

        # removed formatting to count digits only
        digits_only = re.sub(r"\D", "", phone)

        # Check digit count 7-15 digits is reasonable for most phone numbers
        # across the globe minimum digits are 7-8 and maximum is 15
        # source is google on the internet 
        if len(digits_only) < 7 or len(digits_only) > 15:
            return False

        # This check for malicious patterns
        if not self.is_safe_input(phone):
            return False

        return True

    def validate_time_format(self, time_str: str) -> bool:
        """
        This function validates time format and values.

        Args:
            time_str: Time string to validate

        Returns:
            True if time format is valid
        """

        # This checks if time_str if available
        if not time_str:
            return False
        
        # Extract hours and minutes
        time_format_match = re.match(r"(\d{1,2}):(\d{2})(?:\s?(AM|PM|am|pm))?", time_str)
        if not time_format_match:
            return False

        hours, minutes, period = time_format_match.groups()
        # here we performed type casting to perform operations on it.
        hours, minutes = int(hours), int(minutes)

        # Validate minutes
        if minutes > 59:
            return False

        # Validate hours based on format
        if period:  # This means its 12-hour format
            if hours < 1 or hours > 12:
                return False
        else:  # means its 24-hour format
            if hours > 23:
                return False

        return True

    def validate_html_tag(self, tag: str) -> bool:
        """
        This method validates HTML tag existence.

        Args:
            tag: HTML tag to validate

        Returns:
            True if tag appears safe (basic validation)
        """

        # This check for malicious inputs
        if not self.is_safe_input(tag):
            return False

        # Check for dangerous tags
        dangerous_tags = ["script", "iframe", "object", "embed", "link"]
        tag_name = re.match(r"<([a-zA-Z][a-zA-Z0-9]*)", tag)
        if tag_name and tag_name.group(1).lower() in dangerous_tags:
            return False

        return True

    def validate_hashtag(self, hashtag: str) -> bool:
        """
        This method validate hashtag format.

        Args:
            hashtag: Hashtag to validate

        Returns:
            True if hashtag is valid
        """

        # This will make sure that input is not empty
        if not hashtag:
            return False

        # Must have at least one letter (not just numbers)
        if not re.search(r"[a-zA-Z]", hashtag):
            return False

        # This will check for malicious patterns in the input
        if not self.is_safe_input(hashtag):
            return False

        # reasonable length check not longest ones
        if len(hashtag) > 140:
            return False

        return True

    def validate_amount_currency(self, amount: str) -> bool:
        """
        This method validates amount currency format.

        Args:
            amount: Currency amount to validate

        Returns:
            True if amount is valid
        """

        # made sure if amount input is there
        if not amount:
            return False
        
        # Remove $ and commas to get number
        clean_amount = amount.replace("$", "").replace(",", "")

        try:
            value = float(clean_amount)
            # reasonable range check
            # Hhh to prevent imaginable amount or negative ones
            if value < 0 or value > 999999999.99:
                return False
        except ValueError:
            return False

        # Check for malicious inputs
        if not self.is_safe_input(amount):
            return False

        return True

    def validate_credit_card(self, card_number: str) -> bool:
        """
        This method validates credit card using Luhn algorithm.

        Args:
            card: Credit card number to validate

        Returns:
            True if card passes Luhn algorithm check
        """

        # first remove formatting issues like spaces and dashes
        card_digits = re.sub(r"\D", "", card_number)

        # it checks length 13-19 card_digits for valid cards
        # based on type of card but we must be inclusive for reliable system 
        if len(card_digits) < 13 or len(card_digits) > 19:
            return False

        # Reject fake numbers
        if card_digits == "0" * len(card_digits):
            return False

        # Luhn Algorithm implementation
        def luhn_check(card_number):
            """Implementation of Luhn algorithm for card validation."""
            if not card_number.isdigit():
                return False
            
            total = 0
            reverse_card_digits = card_number[::-1]

            for index, digit in enumerate(reverse_card_digits):
                number = int(digit)
                if index % 2 == 1:
                    number *= 2
                    if number > 9:
                        number -= 9
                total += number

            return total % 10 == 0

        return luhn_check(card_digits)

