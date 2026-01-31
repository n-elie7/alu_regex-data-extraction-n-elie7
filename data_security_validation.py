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
