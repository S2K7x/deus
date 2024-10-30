# deus.py - Advanced Asynchronous Endpoint Fuzzer

deus.py is an advanced, parameter-based endpoint fuzzer designed to help security testers identify common vulnerabilities (like SQL injection, XSS, SSRF, and IDOR) in web applications. Leveraging asynchronous requests, deus.py provides efficient fuzzing with custom payload options, rate limiting, and support for different parameter types (query and JSON).

## Features

- Asynchronous fuzzing using `aiohttp` for fast, efficient request handling.
- Vulnerability detection for SQL Injection, XSS, SSRF, and IDOR via payload injections.
- Error pattern matching to identify vulnerabilities based on common error messages.
- Customizable payloads through an external file.
- Rate limiting to control request frequency and prevent server overload.
- Verbose and response-saving modes for detailed logging and post-analysis.

## Requirements

- Python 3.8+
- `requests`, `argparse`, `re`, `asyncio`, `aiohttp`, `colorama`

Install dependencies with:

```bash
pip install -r requirements.txt
```

## Usage

### Basic Command

```bash
python deus.py <url> [OPTIONS]
```

### Options

- `url` (positional): URL to target for fuzzing, e.g., `http://example.com/api/test`.
- `-m`, `--method`: HTTP method to use (GET or POST). Default is GET.
- `-t`, `--type`: Parameter type (query or json). Default is query.
- `-d`, `--data`: Parameter data as key=value pairs, separated by & (e.g., `id=1&name=test`).
- `--headers`: Custom headers as key=value pairs, separated by & (e.g., `Authorization=Bearer token`).
- `--custom-payloads`: Path to a file containing custom payloads, each on a new line.
- `--rate-limit`: Rate limit for requests per second. Default is 5.
- `--save-responses`: Save full responses for further analysis.
- `--verbose`: Enable verbose mode for debugging.

### Examples

1. **Basic Fuzzing:**

   ```bash
   python deus.py http://example.com/api/test -m GET -t query -d "id=1&name=test"
   ```

2. **Custom Headers and POST Method:**

   ```bash
   python deus.py http://example.com/api/test -m POST --headers "Authorization=Bearer token" -d "id=1&name=test"
   ```

3. **Using Custom Payloads with JSON Parameters:**

   ```bash
   python deus.py http://example.com/api/test -m POST -t json -d "id=1&name=test" --custom-payloads custom_payloads.txt
   ```

4. **Saving Responses and Enabling Verbose Output:**

   ```bash
   python deus.py http://example.com/api/test --save-responses --verbose
   ```

## Custom Payloads

To load custom payloads, save them in a text file with each payload on a new line. Use the `--custom-payloads` option to specify the file path.

### Sample Payload File (custom_payloads.txt)

```
' OR '1'='1
<script>alert(1)</script>
http://localhost/admin
```

## Error Patterns and Vulnerability Types

The tool uses predefined patterns for common vulnerabilities:

- **SQL Injection:** Detects syntax errors related to SQL.
- **XSS:** Detects `<script>` tags or JavaScript `onerror` alerts.
- **SSRF:** Identifies access to internal addresses or restricted resources.
- **IDOR:** Matches patterns like “access denied” or “not authorized.”

## Exit Handling

Use `Ctrl+C` to gracefully exit the program. deus.py handles the interrupt signal to terminate fuzzing cleanly.

## Contributing

Feel free to submit issues or pull requests to enhance deus.py!

## License

deus.py is open-source and distributed under the MIT License.
```
