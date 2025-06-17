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

### 🤖 AI-Powered Analysis
- **Intelligent Explanations**: AI explains vulnerabilities and provides remediation suggestions
- **Context Awareness**: Understands code context and project structure
- **Natural Language Interface**: Interact using natural language queries
- **Smart Reporting**: Detailed reports with severity classification

### 🏗️ Architecture
- **MCP Protocol**: JSON-RPC communication with Semgrep MCP server
- **Async Communication**: Efficient handling of multiple scanning operations
- **Error Handling**: Robust error handling with circuit breaker patterns
- **Cross-platform**: Supports Windows, macOS, Linux

## 🚀 Installation

### Prerequisites
- **Python 3.10+**
- **uv package manager** (recommended)
- **Google AI Studio API key**

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

### Option 2: Web UI
```bash
adk web
```
- Open http://localhost:8000 in your browser
- Rich web interface with visual reports
- Drag & drop file uploads

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

## 🧪 Testing Features

### 1. Directory Scanning
Test with the provided vulnerable code examples:

```bash
# Using interactive script
python run_agent.py
# Choose option 1 and enter: examples/

# Using natural language (terminal)
adk run code_scan_agent
# Type: "Scan the examples directory for security vulnerabilities"
```

**Expected Output**: Should detect 10+ vulnerabilities including SQL injection, command injection, hardcoded secrets.

### 2. File-specific Scanning
```bash
# Using interactive script
python run_agent.py
# Choose option 2 and enter: examples/vulnerable_code.py

# Using natural language
# Type: "Check examples/vulnerable_code.py for security issues"
```

### 3. Quick Security Check (Code Snippet)
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

### 4. Language Support
```bash
# Check supported languages
python run_agent.py
# Choose option 4

# Should show 40+ languages: Python, JavaScript, Java, C++, Go, etc.
```

### 5. Custom Rules Testing
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

### 6. Advanced Features

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
