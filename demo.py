#!/usr/bin/env python3
"""
Demo script for Code Scan Agent
Showcases the main features and capabilities of the security scanning tool.
"""
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from code_scan_agent.agent import (
    scan_code_directory,
    quick_security_check,
    get_supported_languages,
    analyze_code_structure
)

def demo_vulnerable_code_detection():
    """Demo: Detecting vulnerabilities in sample code"""
    print("🔍 Demo: Vulnerability Detection")
    print("=" * 50)
    
    # Sample vulnerable code
    vulnerable_code = '''
import sqlite3
import os

def get_user(user_id):
    # SQL Injection vulnerability
    conn = sqlite3.connect('users.db')
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return conn.execute(query).fetchone()

def run_command(user_input):
    # Command injection vulnerability  
    os.system(f"ls -la {user_input}")

# Hardcoded secret
API_KEY = "sk-1234567890abcdef"
'''
    
    print("Scanning vulnerable Python code...")
    result = quick_security_check(vulnerable_code, "python")
    
    if result["status"] == "success":
        scan_result = result.get("result", {})
        findings = scan_result.get("content", [])
        
        if findings:
            print(f"\n🚨 Found {len(findings)} security issues!")
            for i, finding in enumerate(findings[:3], 1):
                rule_id = finding.get("check_id", "unknown")
                message = finding.get("extra", {}).get("message", "No message")
                print(f"  {i}. {rule_id}: {message}")
        else:
            print("✅ No vulnerabilities detected")
    else:
        print(f"❌ Error: {result.get('error_message', 'Unknown error')}")

def demo_directory_scanning():
    """Demo: Scanning the examples directory"""
    print("\n🔍 Demo: Directory Scanning")
    print("=" * 50)
    
    examples_dir = "examples"
    if Path(examples_dir).exists():
        print(f"Scanning directory: {examples_dir}")
        result = scan_code_directory(examples_dir)
        
        if result["status"] == "success":
            total_findings = result.get("total_findings", 0)
            if total_findings > 0:
                print(f"🚨 Found {total_findings} issues")
                
                severity = result.get("severity_breakdown", {})
                if severity:
                    print("📊 Severity breakdown:")
                    for level, count in severity.items():
                        print(f"   • {level}: {count}")
            else:
                print("✅ No issues found")
        else:
            print(f"❌ Error: {result.get('error_message', 'Unknown error')}")
    else:
        print("⚠️ Examples directory not found")

def demo_supported_languages():
    """Demo: Show supported languages"""
    print("\n🌍 Demo: Supported Languages")
    print("=" * 50)
    
    result = get_supported_languages()
    
    if result["status"] == "success":
        languages = result.get("supported_languages", [])
        if languages:
            print("✅ Successfully retrieved supported languages")
            print(f"📊 Total languages supported: {len(languages) if isinstance(languages, list) else 'Multiple'}")
            
            # Parse language information
            if isinstance(languages, list) and len(languages) > 0:
                if isinstance(languages[0], dict):
                    lang_text = languages[0].get("text", "")
                    if "supported languages are:" in lang_text:
                        langs = lang_text.split("supported languages are:")[1].strip()
                        lang_list = [l.strip() for l in langs.split(",")]
                        print(f"📋 Sample languages: {', '.join(lang_list[:10])}")
        else:
            print("⚠️ No language information available")
    else:
        print(f"❌ Error: {result.get('error_message', 'Unknown error')}")

def demo_custom_rule_example():
    """Demo: Example of custom rule usage"""
    print("\n⚙️ Demo: Custom Rule Example")  
    print("=" * 50)
    
    print("Custom Semgrep rule example for detecting eval() usage:")
    print("""
rules:
  - id: detect-eval-usage
    pattern: eval(...)
    message: "Dangerous use of eval() detected - code injection risk"
    severity: ERROR
    languages: [python]
    """)
    
    # Example code that would trigger the rule
    dangerous_code = '''
user_input = input("Enter expression: ")
result = eval(user_input)  # Dangerous!
print(f"Result: {result}")
'''
    
    print("Code that would trigger this rule:")
    print(dangerous_code)
    print("💡 This demonstrates how custom rules can catch specific patterns")

def main():
    """Run all demos"""
    print("🚀 Code Scan Agent - Feature Demo")
    print("=" * 60)
    print("This demo showcases the main features of the security scanning tool.\n")
    
    try:
        # Demo 1: Vulnerability detection
        demo_vulnerable_code_detection()
        
        # Demo 2: Directory scanning
        demo_directory_scanning()
        
        # Demo 3: Language support
        demo_supported_languages()
        
        # Demo 4: Custom rules
        demo_custom_rule_example()
        
        print("\n" + "=" * 60)
        print("🎉 Demo completed!")
        print("\nTo start using the tool interactively:")
        print("  python run_agent.py")
        print("\nFor web interface:")
        print("  adk web")
        print("\nFor terminal chat:")
        print("  adk run code_scan_agent")
        
    except KeyboardInterrupt:
        print("\n👋 Demo interrupted")
    except Exception as e:
        print(f"\n❌ Demo error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 