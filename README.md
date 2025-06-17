# 🔍 Code Scan Agent

A powerful AI-driven code security scanning tool powered by **Google ADK** and **Semgrep MCP** that helps developers identify security vulnerabilities, code quality issues, and potential threats in their codebase.

## 🎯 Overview

Code Scan Agent is an intelligent security scanning solution that combines:
- **Semgrep MCP Server**: Advanced static analysis engine supporting 40+ programming languages
- **Google ADK Framework**: AI-powered analysis and explanations using Gemini 2.0 Flash model
- **Interactive Interface**: Multiple ways to interact with the tool (Web UI, Terminal, API)
- **Comprehensive Detection**: OWASP Top 10 vulnerabilities, code smells, and security best practices

## ✨ Key Features

### 🛡️ Security Scanning
- **Vulnerability Detection**: SQL injection, XSS, Command injection, Path traversal
- **Secret Detection**: Hardcoded API keys, passwords, tokens
- **Code Quality**: Code smells, bad practices, maintainability issues
- **Custom Rules**: Create and use custom Semgrep rules
- **Multi-language Support**: 40+ programming languages including Python, JavaScript, Java, C++, Go, etc.
- **AST Analysis**: Advanced code structure analysis with abstract syntax trees

### 🤖 AI-Powered Analysis
- **Intelligent Explanations**: AI explains vulnerabilities and provides remediation suggestions
- **Context Awareness**: Understands code context and project structure
- **Natural Language Interface**: Interact using natural language queries
- **Smart Reporting**: Detailed reports with severity classification

### 🏗️ Architecture
- **MCP Protocol**: JSON-RPC communication with Semgrep MCP server
- **Async/Sync Communication**: Efficient handling of multiple scanning operations
- **Circuit Breaker Pattern**: Fault tolerance and service protection
- **Comprehensive Error Handling**: Structured error codes and recovery suggestions
- **Cross-platform**: Supports Windows, macOS, Linux
- **Thread-safe Operations**: Safe concurrent scanning operations

### 🔧 Advanced Features
- **Rule Schema Validation**: Get and validate Semgrep rule schemas
- **Directory/File Scanning**: Flexible scanning of directories or specific files
- **Quick Security Checks**: Fast vulnerability detection for code snippets
- **Resource Management**: Automatic cleanup and memory management
- **Health Monitoring**: Built-in health checks and preflight validation

## 🚀 Installation

### Prerequisites
- **Python 3.10+**
- **uv package manager** (recommended)
- **Google AI Studio API key**
- **System Requirements**: Minimum 100MB RAM for optimal performance

### Quick Setup

1. **Clone the repository**:
```bash
git clone <repository-url>
cd code-scan-agent
```

2. **Install uv package manager** (if not already installed):
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.bashrc  # or restart terminal
```

3. **Run the quick setup script**:
```bash
bash quick_start.sh
```

4. **Configure API key**:
   - Get your API key from [Google AI Studio](https://aistudio.google.com/app/apikey)
   - Edit `code_scan_agent/.env` file:
   ```
   GOOGLE_API_KEY=your_google_ai_studio_key_here
   GOOGLE_GENAI_USE_VERTEXAI=FALSE
   ```

### Manual Installation

If you prefer manual setup:

```bash
# Install dependencies
uv sync

# Install ADK
uv add google-adk

# Run setup
python setup.py

# Test installation
python test_agent.py
```

## 🎮 Usage

### Option 1: Interactive Script (Recommended)
```bash
python run_agent.py
```
- Simple menu-driven interface
- No browser required
- Perfect for quick scans

### Option 2: Web UI (Rich Interactive Experience)
```bash
adk web
```
- Open http://localhost:8000 in your browser
- **Chat-based interface**: Ask questions in natural language
- **Visual reports**: Interactive vulnerability summaries
- **File uploads**: Drag & drop files for analysis
- **Real-time results**: Live vulnerability detection
- **Educational mode**: Get explanations about security issues

**Sample Web UI Interactions:**
- "Scan my Python files for SQL injection vulnerabilities"
- "What security issues are in the uploaded code?"
- "Explain this vulnerability and how to fix it"
- "Create a security report for my project"

### Option 3: Terminal Interface
```bash
adk run code_scan_agent
```
- Direct chat with the AI agent
- Natural language commands
- Ideal for developers who prefer CLI

### Option 4: API Server
```bash
adk api_server --port 8080
```
- RESTful API endpoints
- Integration with other tools
- Programmatic access

## 📚 API Documentation

### Available Functions

- `scan_code_directory(directory_path, config=None)` - Scan toàn bộ thư mục
- `scan_code_files(file_paths, config=None)` - Scan danh sách files cụ thể  
- `quick_security_check(code_content, language)` - Check nhanh code snippet
- `scan_with_custom_rule(code_content, rule, language)` - Scan với custom rule
- `get_supported_languages()` - Lấy danh sách ngôn ngữ được hỗ trợ
- `analyze_code_structure(code_content, language)` - Phân tích cấu trúc code
- `get_semgrep_rule_schema()` - Lấy schema cho Semgrep rules

### Error Handling

Code Scan Agent sử dụng hệ thống error handling toàn diện với:

- **Structured Error Codes**: Mã lỗi chuẩn hóa (E1001-E9099)
  - E1xxx: Input validation errors
  - E2xxx: Semgrep client errors  
  - E3xxx: MCP protocol errors
  - E4xxx: Scan operation errors
  - E5xxx: System/infrastructure errors
  - E6xxx: Configuration errors
- **Severity Levels**: CRITICAL, HIGH, MEDIUM, LOW, INFO
- **Circuit Breaker**: Tự động ngăn chặn requests khi service lỗi
- **Recovery Suggestions**: Gợi ý khắc phục cụ thể cho từng loại lỗi
- **Context Tracking**: Thông tin đầy đủ về component và operation bị lỗi

### Response Format

All API functions return structured responses:

```python
{
    "status": "success|error",
    "result": {...},           # Scan results (on success)
    "error_code": "E1001",     # Error code (on error)
    "error_message": "...",    # Error description
    "severity": "high",        # Error severity
    "recovery_suggestion": "...", # How to fix
    "timestamp": "2024-01-01T..."
}
```

## 🧪 Testing Features

### 1. Web UI Testing (Recommended for rich interface)

Start the Web UI:
```bash
adk web
# Open http://localhost:8000 in your browser
```

#### Test Questions & Expected Outputs:

**🔍 Directory Scanning:**
```
Question: "Scan the examples directory for security vulnerabilities"
Expected Output: Interactive report showing 10+ vulnerabilities with:
- Severity breakdown (Critical, High, Medium, Low)
- File locations with line numbers
- Detailed vulnerability descriptions
- Remediation suggestions
```

**📄 File Analysis:**
```
Question: "Analyze examples/vulnerable_code.py for security issues"
Expected Output: Detailed analysis showing:
- SQL injection in get_user_by_id() function (line 12)
- Command injection in run_command() function (line 25)
- Hardcoded credentials (lines 35-37)
- Weak cryptography usage (MD5 hash)
```

**🔒 Code Snippet Security Check:**
```
Question: "Check this Python code for security issues:
import os
password = 'hardcoded123'
os.system(f'mysql -u root -p{password}')"

Expected Output:
- Hardcoded password detected (severity: HIGH)
- Command injection vulnerability (severity: CRITICAL)
- Recommendations for secure alternatives
```

**🌍 Language Support Query:**
```
Question: "What programming languages does this tool support?"
Expected Output: List of 40+ supported languages including:
Python, JavaScript, Java, C++, Go, PHP, Ruby, Rust, TypeScript, etc.
```

**⚙️ Custom Security Rules:**
```
Question: "Create a custom rule to detect dangerous eval() usage in Python"
Expected Output: 
- Sample Semgrep rule in YAML format
- Explanation of rule components
- Test code example that would trigger the rule
```

**🏗️ Architecture Analysis:**
```
Question: "Analyze the code structure and suggest security improvements for my Django project"
Expected Output:
- AST analysis of uploaded files
- Security architecture recommendations
- Best practices for secure coding
```

**📋 Rule Schema Validation:**
```
Question: "Get the Semgrep rule schema for creating custom rules"
Expected Output:
- Complete JSON schema for Semgrep rules
- Field descriptions and validation rules
- Examples of valid rule structures
```

**⚡ Performance & Health Monitoring:**
```
Question: "Check system health and performance metrics"
Expected Output:
- Circuit breaker status for all services
- Error frequency statistics
- Resource usage monitoring
- Service health checks
```

**🚨 Vulnerability Explanation:**
```
Question: "Explain what SQL injection is and how to prevent it"
Expected Output:
- Clear explanation of SQL injection attacks
- Code examples showing vulnerable vs secure patterns
- Prevention techniques (parameterized queries, ORMs)
```

**📊 Project Security Assessment:**
```
Question: "Give me a comprehensive security assessment of my entire codebase"
Expected Output:
- Executive summary with risk score
- Vulnerability categories breakdown
- Priority recommendations
- Compliance checklist (OWASP Top 10)
```

### 2. Interactive Script Testing

```bash
# Using interactive script
python run_agent.py
# Choose option 1 and enter: examples/

# Using natural language (terminal)
adk run code_scan_agent
# Type: "Scan the examples directory for security vulnerabilities"
```

**Expected Output**: Should detect 10+ vulnerabilities including SQL injection, command injection, hardcoded secrets.

### 3. File-specific Scanning
```bash
# Using interactive script
python run_agent.py
# Choose option 2 and enter: examples/vulnerable_code.py

# Using natural language
# Type: "Check examples/vulnerable_code.py for security issues"
```

### 4. Quick Security Check (Code Snippet)
```bash
# Using interactive script
python run_agent.py
# Choose option 3 and paste code

# Example vulnerable code to test:
import os
password = "hardcoded123"
os.system(f"mysql -u root -p{password}")
```

**Expected Output**: Should detect hardcoded credentials and command injection.

### 5. Language Support
```bash
# Check supported languages
python run_agent.py
# Choose option 4

# Should show 40+ languages: Python, JavaScript, Java, C++, Go, etc.
```

### 6. Custom Rules Testing
Create a custom Semgrep rule:

```yaml
rules:
  - id: detect-eval-usage
    pattern: eval(...)
    message: "Dangerous use of eval() detected"
    severity: ERROR
    languages: [python]
```

Test with:
```python
# Vulnerable code
user_input = "1+1"
result = eval(user_input)  # Should be detected
```

### 7. Advanced Features

#### AST Analysis
```bash
# Terminal interface
adk run code_scan_agent
# Type: "Analyze the AST structure of examples/vulnerable_code.py"
```

#### Multi-file Scanning
```bash
# Interactive script
python run_agent.py
# Choose option 2 and enter: file1.py,file2.py,file3.py
```

### 8. Demo Script Testing
```bash
# Run the comprehensive demo
python demo.py

# Expected Output: Showcases all major features with sample results
```

## 🐛 Troubleshooting

### Common Issues

#### 1. "uvx not found" Error
```bash
# Install uv first
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.bashrc
```

#### 2. Web UI 404 Errors
If `adk web` shows 404 for static files:
- Use the interactive script: `python run_agent.py`
- Or use terminal interface: `adk run code_scan_agent`

#### 3. API Key Issues
- Ensure your API key is valid
- Check the `.env` file configuration
- Test with: `python test_agent.py`

#### 4. Permission Errors
```bash
# On Unix systems
chmod +x quick_start.sh
chmod +x run_agent.py
```

### Performance Tips

- **Large codebases**: Use directory scanning instead of individual files
- **Timeouts**: Increase timeout in configuration for large scans
- **Memory**: Ensure at least 512MB RAM available for scanning

## 📊 Example Scan Results

### Vulnerability Detection
```
🚨 Security Issues Found: 8
📊 Severity Breakdown:
   • CRITICAL: 2 (SQL Injection, Command Injection)
   • HIGH: 3 (Hardcoded Secrets)
   • MEDIUM: 2 (Weak Cryptography)
   • LOW: 1 (Code Quality)

📋 Detailed Issues:
1. 🔴 SQL Injection (sqlalchemy-sql-injection)
   📁 File: examples/vulnerable_code.py:12
   💬 User input used in SQL query without parameterization
   
2. 🔴 Command Injection (subprocess-shell-true)
   📁 File: examples/vulnerable_code.py:25
   💬 Subprocess call with shell=True and user input
```

### Supported Languages
```
📋 Semgrep supports 40+ languages:
   A: APEX, Arduino, Bash
   C: C, C++, C#, Cairo, Clojure
   D: Dart, Dockerfile
   E: Elixir, Elm
   G: Go, GraphQL
   H: HTML, Hack
   J: Java, JavaScript, JSON, Julia
   K: Kotlin
   L: Lua
   O: OCaml
   P: PHP, Python
   R: R, Ruby, Rust
   S: Scala, Scheme, Solidity, Swift
   T: Terraform, TypeScript
   V: Vue, YAML
```

## 🏗️ Project Structure

```
code-scan-agent/
├── code_scan_agent/          # Main package
│   ├── __init__.py
│   ├── agent.py             # Core agent with 6 scanning tools
│   ├── semgrep_client.py    # MCP client implementation
│   ├── config.py            # Configuration management
│   ├── errors.py            # Enhanced error handling
│   └── .env                 # Environment configuration
├── examples/                 # Test files with vulnerabilities
│   └── vulnerable_code.py   # Sample vulnerable code
├── tests/                    # Test suite
│   ├── test_agent.py
│   └── test_error_handling.py
├── pyproject.toml           # Dependencies and project config
├── quick_start.sh           # Automated setup script
├── run_agent.py            # Interactive script runner
└── README.md               # This file
```

## 🛡️ Security Patterns Detected

### OWASP Top 10 Coverage
- **A01: Broken Access Control** ✅
- **A02: Cryptographic Failures** ✅ 
- **A03: Injection** ✅ (SQL, Command, LDAP, etc.)
- **A04: Insecure Design** ✅
- **A05: Security Misconfiguration** ✅
- **A06: Vulnerable Components** ✅
- **A07: Authentication Failures** ✅
- **A08: Software Integrity Failures** ✅
- **A09: Logging Failures** ✅
- **A10: SSRF** ✅

### Specific Patterns
- SQL injection via string formatting/concatenation
- XSS through unescaped output
- Command injection via `os.system()`, `subprocess`
- Hardcoded secrets (API keys, passwords, tokens)
- Weak cryptography (MD5, SHA1)
- Path traversal vulnerabilities
- Unsafe deserialization
- Information disclosure
- Insecure randomness
- XXE vulnerabilities

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new features
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: Check this README for common issues
- **Issues**: Report bugs on GitHub Issues
- **Testing**: Use `examples/vulnerable_code.py` for testing

---

**⚡ Quick Start Command**:
```bash
bash quick_start.sh && python run_agent.py
```
