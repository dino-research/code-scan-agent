#!/usr/bin/env python3
"""
Test script cho Code Scan Agent
"""
import sys
import os
from pathlib import Path
import asyncio
import logging

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Import components
from code_scan_agent.config import get_config
from code_scan_agent.agent import (
    get_semgrep_client,
    scan_code_directory,
    scan_code_files,
    quick_security_check,
    get_supported_languages
)

# Cấu hình logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_config():
    """Test cấu hình"""
    print("🔧 Testing configuration...")
    config = get_config()
    config.print_config()
    
    assert config.validate(), "Configuration invalid!"
    print("✅ Configuration valid!")

def test_configuration():
    """Test cấu hình agent"""
    print("🔧 Testing configuration...")
    
    # Load config
    config = get_config()
    
    # Hiển thị thông tin cấu hình
    print("🔧 Cấu hình Code Scan Agent:")
    print(f"   • Semgrep Timeout: {config.get('SEMGREP_TIMEOUT')}s")
    print(f"   • Default Rules: {config.get('SEMGREP_DEFAULT_RULES')}")
    print(f"   • Max File Size: {config.get('MAX_FILE_SIZE_MB')}MB")
    print(f"   • Intelligent Scanning: {'Enabled' if config.get('INTELLIGENT_SCANNING_ENABLED') else 'Disabled'}")
    
    assert config.validate(), "Configuration invalid!"

def test_list_tools():
    """Test lấy danh sách tools có sẵn"""
    try:
        client = get_semgrep_client()
        tools = client.list_tools()
        assert tools is not None, "Failed to get tools list"
        
        # Return tools without using return statement
        tools_result = {
            "status": "success",
            "tools": tools
        }
        
        # Store result as a global variable for test_tools_list to use
        global tools_list_result
        tools_list_result = tools_result
        
    except Exception as e:
        logger.error(f"Lỗi khi list tools: {e}")
        assert False, f"Error listing tools: {e}"

def test_tools_list():
    """Test list available tools"""
    print("🔧 Testing available tools...")
    
    # Call test_list_tools to populate tools_list_result
    test_list_tools()
    
    # Use the global variable
    global tools_list_result
    assert tools_list_result["status"] == "success", "Failed to get tools list"
    
    tools = tools_list_result["tools"]
    print(f"✅ Found {len(tools)} available tools")
    for tool in tools:
        print(f"   • {tool.get('name', 'unnamed')}: {tool.get('description', 'no description')}")

def test_supported_languages():
    """Test lấy danh sách ngôn ngữ"""
    print("\n🌍 Testing supported languages...")
    try:
        result = get_supported_languages()
        assert result["status"] == "success", f"Failed: {result.get('error_message', 'Unknown error')}"
        
        languages = result["supported_languages"]
        print(f"✅ Found {len(languages)} supported languages")
        print(f"   Sample languages: {languages[:10]}...")
    except Exception as e:
        assert False, f"Exception: {e}"

def test_quick_security_check():
    """Test quick security check"""
    print("\n🔍 Testing quick security check...")
    
    # Code có lỗ hổng SQL injection
    vulnerable_code = """
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('db.sqlite')
    query = f'SELECT * FROM users WHERE id = {user_id}'
    return conn.execute(query).fetchone()
"""
    
    try:
        result = quick_security_check(vulnerable_code, "python")
        assert result["status"] == "success", f"Failed: {result.get('error_message', 'Unknown error')}"
        
        print("✅ Quick security check completed")
        print(f"   Language: {result['language']}")
        
        # Kiểm tra xem có tìm thấy lỗ hổng không
        scan_result = result.get("result", {})
        if "content" in scan_result:
            findings = scan_result["content"]
            if isinstance(findings, list) and len(findings) > 0:
                print(f"   🚨 Found {len(findings)} security issues!")
                for finding in findings[:3]:  # Show first 3
                    if isinstance(finding, dict):
                        rule_id = finding.get("check_id", "unknown")
                        message = finding.get("extra", {}).get("message", "No message")
                        print(f"     • {rule_id}: {message}")
            else:
                print("   ✅ No security issues found")
    except Exception as e:
        assert False, f"Exception: {e}"

def test_scan_examples():
    """Test scan examples directory"""
    print("\n📁 Testing directory scan...")
    
    examples_dir = Path("examples")
    if not examples_dir.exists():
        print("⚠️  Examples directory not found, skipping test")
        return
    
    try:
        result = scan_code_directory(str(examples_dir))
        assert result["status"] == "success", f"Failed: {result.get('error_message', 'Unknown error')}"
        
        if "total_findings" in result:
            print(f"✅ Directory scan completed")
            print(f"   Total findings: {result['total_findings']}")
            if result["total_findings"] > 0:
                print(f"   Summary: {result.get('summary', 'No summary')}")
                severity = result.get("severity_breakdown", {})
                if severity:
                    print(f"   Severity breakdown: {severity}")
        else:
            print("✅ Directory scan completed (basic result)")
    except Exception as e:
        assert False, f"Exception: {e}"

def main():
    """Hàm chính"""
    print("🧪 Code Scan Agent - Test Suite")
    print("=" * 40)
    
    tests = [
        ("Configuration", test_config),
        ("Available Tools", test_tools_list),
        ("Supported Languages", test_supported_languages), 
        ("Quick Security Check", test_quick_security_check),
        ("Directory Scan", test_scan_examples),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} failed with exception: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n📊 Test Results:")
    print("=" * 40)
    
    passed = 0
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} {test_name}")
        if result:
            passed += 1
    
    print(f"\n📈 Results: {passed}/{len(results)} tests passed")
    
    if passed == len(results):
        print("🎉 All tests passed! Agent is ready to use.")
        print("\n🚀 Next steps:")
        print("1. Run: adk web")
        print("2. Open: http://localhost:8000")
        print("3. Select: code_scan_agent")
        return 0
    else:
        print("⚠️  Some tests failed. Check configuration and dependencies.")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 