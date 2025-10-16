# Utilities Documentation

This directory contains utility scripts and tools for managing parsers, sending events, and maintaining the jarvis_coding project.

## Table of Contents
- [Parser Management](#parser-management)
- [Continuous Data Senders](#continuous-data-senders)
- [Event Testing](#event-testing)
- [Code Maintenance](#code-maintenance)

---

## Parser Management

### 📄 `create_sentinelone_parsers.py`
**Purpose:** Creates SentinelOne parser directories from JSON configuration files.

**Usage:**
```bash
python utilities/create_sentinelone_parsers.py
```

**Features:**
- Reads parser definitions from JSON files
- Creates proper directory structure with metadata.yaml
- Fixes common JSON syntax issues
- Supports multiple input file locations

**Required Files:**
- `sentinelone_parsers.json` or `sentinelone_parsers_example.json`

**Output:**
- Creates directories in `parsers/sentinelone/`
- Each parser gets its own directory with `.json` and `metadata.yaml` files

---

### 📥 `download_sentinelone_parsers.py`
**Purpose:** Downloads parser configurations from the official SentinelOne AI SIEM GitHub repository.

**Usage:**
```bash
# List available parsers without downloading
python utilities/download_sentinelone_parsers.py --list

# Download all parsers
python utilities/download_sentinelone_parsers.py
```

**Features:**
- Downloads from https://github.com/Sentinel-One/ai-siem
- Supports both community (148) and sentinelone (17) parsers
- Creates parser inventory JSON file
- Handles GitHub API rate limiting

**Output:**
- Downloads to `parsers/community_new/` and `parsers/sentinelone_new/`
- Creates `parsers/parser_inventory.json` with download summary

---

### 📋 `official_parser_mapping.json`
**Purpose:** Maps generators to their corresponding official parsers.

**Structure:**
```json
{
  "Parser Name": {
    "current_generator": "generator_file.py",
    "current_parser": "parser-name-latest",
    "ocsf_class": "Network Activity (4001)",
    "priority": "HIGH"
  }
}
```

**Usage:**
- Reference for generator-parser alignment
- Used by HEC sender for sourcetype mapping
- Priority levels: HIGH, MEDIUM, LOW

---

## Continuous Data Senders

### 🔄 `continuous_senders/continuous_data_sender_v2.py`
**Purpose:** Continuously sends realistic security events to SentinelOne HEC endpoint.

**Usage:**
```bash
python utilities/continuous_senders/continuous_data_sender_v2.py
```

**Features:**
- Sends events for PingFederate, AWS CloudTrail, and FortiGate
- 10 events per service every 30 seconds
- Direct HEC integration (no dependency on hec_sender.py)
- Graceful shutdown with Ctrl+C

**Configuration:**
```python
HEC_TOKEN = "your-token-here"
HEC_URL = "https://ingest.us1.sentinelone.net/services/collector"
```

**Output:**
- Sends 180 total events per minute (60 per service)
- Shows real-time status updates
- Handles authentication errors gracefully

---

### 🔄 `continuous_senders/continuous_data_sender.py`
**Purpose:** Original continuous sender using subprocess calls to hec_sender.py.

**Usage:**
```bash
export S1_HEC_TOKEN="your-token-here"
python utilities/continuous_senders/continuous_data_sender.py
```

**Features:**
- Uses hec_sender.py for event sending
- Supports multiple PingIdentity products
- Configurable batch size and intervals
- Thread-based parallel sending

---

## Event Testing

### 🔑 `send_key_events.py`
**Purpose:** Sends specific test events to validate parser functionality.

**Usage:**
```bash
python utilities/send_key_events.py --product <product_name> --count <number>
```

**Features:**
- Sends targeted events for specific products
- Useful for parser validation
- Supports custom event counts
- Direct HEC integration

**Example:**
```bash
# Send 5 AWS CloudTrail events
python utilities/send_key_events.py --product aws_cloudtrail --count 5

# Send 10 FortiGate events
python utilities/send_key_events.py --product fortinet_fortigate --count 10
```

---

## Code Maintenance

### 🔧 `update_imports.py`
**Purpose:** Updates import statements across the codebase.

**Usage:**
```bash
python utilities/update_imports.py
```

**Features:**
- Batch updates import statements
- Handles module reorganization
- Updates relative imports to absolute
- Preserves code functionality

**Use Cases:**
- After moving modules to different directories
- Standardizing import patterns
- Refactoring module names

---

## Configuration Files

### `sentinelone_parsers_example.json`
Example parser configuration file showing the expected JSON structure for `create_sentinelone_parsers.py`.

**Structure:**
```json
{
  "parsers": [
    {
      "attributes": {
        "dataSource.vendor": "Vendor Name",
        "dataSource.name": "Product Name",
        "dataSource.category": "security"
      },
      "formats": [...]
    }
  ]
}
```

---

## Testing Utilities

To test if utilities are working:

### 1. Test Parser Download (List Only)
```bash
cd utilities
python download_sentinelone_parsers.py --list
```
Expected: Lists 148 community and 17 sentinelone parsers

### 2. Test Continuous Sender (Dry Run)
```bash
# Check if script loads without errors
python -c "import utilities.continuous_senders.continuous_data_sender_v2"
```

### 3. Test Send Key Events
```bash
python utilities/send_key_events.py --help
```
Expected: Shows usage instructions

---

## Environment Variables

Required environment variables for utilities:

```bash
# HEC Token for SentinelOne
export S1_HEC_TOKEN="your-hec-token-here"

# Optional: Custom HEC URLs
export S1_HEC_EVENT_URL_BASE="https://ingest.us1.sentinelone.net/services/collector/event"
export S1_HEC_RAW_URL_BASE="https://ingest.us1.sentinelone.net/services/collector/raw"

# SDL API Token (for validation)
export S1_SDL_API_TOKEN="your-sdl-api-token"
```

---

## Troubleshooting

### Common Issues:

1. **401 Unauthorized Error**
   - Check HEC token is valid
   - Verify token has correct permissions
   - Ensure using correct HEC URL

2. **Module Import Errors**
   - Run from project root directory
   - Ensure Python path includes project root
   - Check virtual environment is activated

3. **Parser Download Timeout**
   - GitHub API rate limiting
   - Try again after waiting
   - Use `--list` flag to verify connectivity first

4. **JSON Parsing Errors**
   - Check JSON syntax in configuration files
   - Use online JSON validator
   - Review error message for line number

---

## Best Practices

1. **Always test with small batches first**
   ```bash
   python utilities/send_key_events.py --product test --count 1
   ```

2. **Use virtual environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Check logs for errors**
   - Review console output
   - Check HEC response codes
   - Verify events in SentinelOne UI

4. **Backup before updates**
   - Copy parsers before modifications
   - Use version control for changes
   - Test in development first

---

## Support

For issues or questions:
1. Check this documentation
2. Review error messages carefully
3. Verify environment variables
4. Test with minimal examples
5. Check GitHub repository for updates