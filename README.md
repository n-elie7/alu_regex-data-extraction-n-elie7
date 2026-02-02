# Regular Expression Formative
## Data Extraction & Secure Validation Assignment

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

A robust Python-based system for extracting structured data from raw text using regex patterns while implementing security measures to prevent malicious input exploitation.

## Key Features

- **8 Data Type Extractors**: Email, URL, Phone, Credit Card, Time, HTML Tags, Hashtags, Currency amount
- **Security-First Design**: Built-in detection for SQL injection, XSS, and path traversal attacks
- **Smart Validation**: Multi-layer validation beyond regex pattern matching
- **Sensitive Data Protection**: Automatic masking of credit cards and PII in outputs
- **Production-Ready**: Handles realistic data variations and edge cases

## Getting Started

### Prerequisites

- Python 3.8+

### Installation

1. Clone the repository:
```bash
git clone https://github.com/n-elie7/alu_regex-data-extraction-n-elie7.git
cd alu_regex-data-extraction-n-elie7
```

2. Verify Python installation:
```bash
python3 --version
```

### Usage

Run the extraction script:
```bash
python3 data_security_validation.py
```

The script will:
1. Read data from `test_input.txt`
2. Extract and validate all supported data types
3. Detect security threats
4. Output results to console
5. Save results to `valid_results_extracted.json`

## Data Types Supported

### 1. Email Addresses
**Pattern**: `user@example.com`, `firstname.lastname@company.co.uk`

**Regex Pattern**:
```python
r'\b[a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]@[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}\b'
```

**Validation Checks**:
- Length validation (RFC 5321 compliance)
- No consecutive dots
- Valid domain structure
- SQL injection prevention

**Examples**:
- Valid: `john.doe@example.com`, `user+tag@subdomain.company.org`
- Invalid: `@nodomain.com`, `user@`, `user@@domain.com`

### 2. URLs
**Pattern**: `https://www.example.com`, `https://subdomain.example.org/page`

**Regex Pattern**:
```python
r'https?://(?:www\.)?[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}(?:/[^\s]*)?'
```

**Security Features**:
- Blocks dangerous protocols (`javascript:`, `data:`, `file:`)
- XSS pattern detection
- URL length validation (max 2048 chars)

**Examples**:
- Valid: `https://example.com`, `https://api.service.com/v2/endpoint`
- Invalid: `javascript:alert('xss')`, `htp://wrong.com`

### 3. Phone Numbers
**Pattern**: `(123) 456-7890`, `123-456-7890`, `+1-555-123-4567`

**Regex Pattern**:
```python
r'(?:\+\d{1,3}[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}\b'
```

**Validation Checks**:
- 7-15 digits (international support)
- Multiple format support
- SQL injection prevention

**Examples**:
- Valid: `(555) 123-4567`, `555.987.6543`, `+1-212-555-0199`
- Invalid: `123` (too short), `555-CALL-NOW` (letters)

### 4. Credit Card Numbers
**Pattern**: `1234 5678 9012 3456`, `1234-5678-9012-3456`

**Regex Pattern**:
```python
r'\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{4}[-\s]?\d{6}[-\s]?\d{5}\b'
```

**Security Features**:
- **Luhn algorithm validation** for card authenticity
- **Automatic masking** in output: `****-****-****-3456`
- Supports Visa, Mastercard, Amex, Discover
- Rejects obvious fakes (all zeros)

**Examples**:
- Valid: Cards that pass Luhn check (shown masked in output)
- Invalid: `0000-0000-0000-0000`, `1234-567X-9012-3456`

### 5. Time Formats
**Pattern**: `14:30` (24-hour), `2:30 PM` (12-hour)

**Regex Pattern**:
```python
r'\b(?:[01]?\d|2[0-3]):[0-5]\d(?:\s?(?:AM|PM|am|pm))?\b'
```

**Validation Checks**:
- Hour validation: 0-23 (24h) or 1-12 (12h)
- Minute validation: 0-59
- Case-insensitive AM/PM

**Examples**:
- Valid: `09:30`, `12:00 PM`, `23:59`
- Invalid: `25:00`, `12:60`, `99:99`

### 6. HTML Tags
**Pattern**: `<p>`, `<div class="example">`, `<img src="image.jpg">`

**Regex Pattern**:
```python
r'<[a-zA-Z][a-zA-Z0-9]*(?:\s+[a-zA-Z][a-zA-Z0-9-]*(?:\s*=\s*(?:"[^"]*"|\'[^\']*\'|[^\s>]+))?)*\s*/?>'
```

**Security Purpose**:
- Primarily used to **detect** potential XSS attacks
- Blocks dangerous tags: `<script>`, `<iframe>`, `<object>`
- Validates proper tag structure

**Examples**:
- Detected (safe): `<p>`, `<div class="content">`
- Blocked: `<script>alert('xss')</script>`, `<iframe src="malicious">`

### 7. Hashtags
**Pattern**: `#Example`, `#ThisIsAHashtag`, `#Tech2025`

**Regex Pattern**:
```python
r'#[a-zA-Z][a-zA-Z0-9_]*\b'
```

**Validation Checks**:
- Must contain at least one letter
- Length limit (140 characters)
- XSS prevention

**Examples**:
- Valid: `#Python`, `#AI2025`, `#Data_Science`
- Invalid: `#` (empty), `#1234` (numbers only)

### 8. Currency Amounts
**Pattern**: `$19.99`, `$1,234.56`

**Regex Pattern**:
```python
r'\$\d{1,3}(?:,\d{3})*(?:\.\d{2})?\b'
```

**Validation Checks**:
- Proper decimal format (exactly 2 places or none)
- Thousands separator support
- Range validation (0 to 999,999,999.99)

**Examples**:
- Valid: `$49.99`, `$1,234.56`, `$2,500`
- Invalid: `$$50.99`, `$50.999` (too many decimals)

## Security Features

### Threat Detection

The system actively scans for and reports:

#### 1. SQL Injection
Detects patterns like:
- `'; DROP TABLE users; --`
- `OR 1=1; DELETE FROM accounts`
- `SELECT * FROM sensitive_data`

#### 2. Cross-Site Scripting (XSS)
Identifies attempts such as:
- `<script>alert('xss')</script>`
- `javascript:malicious_code()`
- `<img src=x onerror=alert('xss')>`

#### 3. Path Traversal
Catches patterns like:
- `../../../etc/passwd`
- `..\..\windows\system32`

### Data Protection

- **Credit card numbers**: Automatically masked in all outputs
- **Sensitive data**: Partial masking available for emails and other PII
- **No storage**: Sensitive data never written to logs in clear text

### Validation Layers

1. **Regex matching**: Initial pattern recognition
2. **Format validation**: Structure and length checks
3. **Security scanning**: Malicious pattern detection
4. **Business logic**: Domain-specific rules (e.g., Luhn algorithm for cards)

## Project Structure

```
alu_regex-data-extraction-n-elie7/
├── data_security_validation.py           # Main extraction script
├── sample_input.txt                      # Realistic test data with valid/invalid patterns
├── valid_results_extracted.json          # output
└── README.md                             # This file description
```

## Sample Output

### Console Output
```
=============================
SECURE DATA EXTRACTION SYSTEM
=============================

Successfully read test input from test_input.txt

Processing data extraction...
Scanning for security threats...

JSON results saved to valid_results_extracted.json
```

### JSON Output Structure
```json
{
  "extracted_data": {
    "emails": ["user@example.com", ...],
    "urls": ["https://example.com", ...],
    "phones": ["(555) 123-4567", ...],
    ...
  },
  "security_threats": {
    "sql_injection": ["'; DROP TABLE users; --", ...],
    "xss_attempts": ["<script>alert('xss')</script>", ...],
    "path_traversal": ["../../../etc/passwd", ...]
  },
  "summary": {
    "total_patterns_found": 83,
    "threats_detected": 14
  }
}
```

## Adding New Data Types

1. Add regex pattern to `__init__` method
2. Create validation function
3. Add extraction logic to `validate_extract_data` method
4. Update documentation

## Author

**Niyubwayo Irakoze Elie**  

## Resources used

- Regex pattern testing: [regex101.com](https://regex101.com)
- Python documentation: [docs.python.org](https://docs.python.org)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [Python Regular Expression HOWTO](https://docs.python.org/3/howto/regex.html)
- [PCI DSS Standards](https://www.pcisecuritystandards.org/) (for payment data security)
