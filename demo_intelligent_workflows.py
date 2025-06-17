#!/usr/bin/env python3
"""
Demo Intelligent Workflows - Code Scan Agent

Test script để demo intelligent workflows cho tất cả tools trong root agent
Showcases ADK Sequential Workflow Agents implementation.

Based on: https://google.github.io/adk-docs/agents/workflow-agents/
"""

import json
import sys
from pathlib import Path
from typing import Dict, Any

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from code_scan_agent.agent import (
    scan_code_files,
    quick_security_check,
    scan_with_custom_rule,
    get_supported_languages,
    analyze_code_structure,
    get_semgrep_rule_schema,
    analyze_project_architecture
)

def print_banner():
    """Print demo banner"""
    print("=" * 80)
    print("🤖 INTELLIGENT WORKFLOWS DEMO - CODE SCAN AGENT")
    print("🔧 Powered by ADK Sequential Workflow Agents")
    print("📚 Based on: https://google.github.io/adk-docs/agents/workflow-agents/")
    print("=" * 80)

def print_section(title: str):
    """Print section header"""
    print(f"\n{'='*60}")
    print(f"🧠 {title}")
    print("="*60)

def format_result(result: Dict[str, Any], show_workflow_metadata: bool = True):
    """Format and print result với workflow metadata"""
    if not isinstance(result, dict):
        print(f"❌ Invalid result format: {type(result)}")
        return
    
    status = result.get("status", "unknown")
    print(f"📊 Status: {status}")
    
    if status == "error":
        print(f"❌ Error: {result.get('error_message', 'Unknown error')}")
        return
    
    # Show workflow metadata if available
    if show_workflow_metadata and "workflow_metadata" in result:
        metadata = result["workflow_metadata"]
        print(f"\n🤖 Workflow Intelligence:")
        print(f"   • Type: {metadata.get('workflow_type', 'unknown')}")
        
        if metadata.get("workflow_type") == "sequential_intelligent":
            features = metadata.get("intelligence_features", {})
            print(f"   • Context Analysis: {'✅' if features.get('context_analysis') else '❌'}")
            print(f"   • Parameter Optimization: {'✅' if features.get('parameter_optimization') else '❌'}")
            print(f"   • Enhanced Execution: {'✅' if features.get('enhanced_execution') else '❌'}")
            
            summary = metadata.get("workflow_summary", {})
            if summary:
                print(f"   • Requirements: {summary.get('requirements_identified', {})}")
                print(f"   • Intelligence Level: {summary.get('intelligence_level', 'standard')}")
    
    # Show main result content
    if "total_findings" in result:
        print(f"🔍 Findings: {result['total_findings']}")
    
    if "summary" in result:
        print(f"📋 Summary: {result['summary']}")

def demo_scan_code_files():
    """Demo scan_code_files với intelligent workflow"""
    print_section("DEMO 1: Intelligent File Scanning")
    
    # Test files
    test_files = ["examples/test_vulnerable.py"]
    
    print("🔍 Testing với intelligent workflow...")
    intelligent_result = scan_code_files(test_files, intelligent=True)
    format_result(intelligent_result)
    
    print("\n🏛️ Testing với traditional mode...")
    traditional_result = scan_code_files(test_files, intelligent=False)
    format_result(traditional_result, show_workflow_metadata=False)
    
    print("\n📊 Comparison:")
    print(f"   • Intelligent findings: {intelligent_result.get('total_findings', 0)}")
    print(f"   • Traditional findings: {traditional_result.get('total_findings', 0)}")

def demo_quick_security_check():
    """Demo quick_security_check với intelligent analysis"""
    print_section("DEMO 2: Intelligent Quick Security Check")
    
    # Vulnerable Python code
    vulnerable_code = """
import subprocess
import os

def dangerous_function(user_input):
    # This is vulnerable to command injection
    result = subprocess.call(user_input, shell=True)
    
    # This is also dangerous
    eval(user_input)
    
    # Direct SQL without parameterization
    query = f"SELECT * FROM users WHERE id = {user_input}"
    
    return result
"""
    
    print("🔍 Testing với intelligent workflow...")
    intelligent_result = quick_security_check(vulnerable_code, "python", intelligent=True)
    format_result(intelligent_result)
    
    print("\n🏛️ Testing với traditional mode...")
    traditional_result = quick_security_check(vulnerable_code, "python", intelligent=False)
    format_result(traditional_result, show_workflow_metadata=False)

def demo_custom_rule_scan():
    """Demo scan_with_custom_rule với intelligent optimization"""
    print_section("DEMO 3: Intelligent Custom Rule Scanning")
    
    test_code = """
import hashlib
password = "admin123"
hashed = hashlib.md5(password.encode()).hexdigest()
"""
    
    custom_rule = """
rules:
  - id: weak-hash-md5
    pattern: hashlib.md5(...)
    message: MD5 is cryptographically weak
    languages: [python]
    severity: WARNING
"""
    
    print("🔍 Testing với intelligent workflow...")
    intelligent_result = scan_with_custom_rule(test_code, custom_rule, "python", intelligent=True)
    format_result(intelligent_result)
    
    print("\n🏛️ Testing với traditional mode...")
    traditional_result = scan_with_custom_rule(test_code, custom_rule, "python", intelligent=False)
    format_result(traditional_result, show_workflow_metadata=False)

def demo_supported_languages():
    """Demo get_supported_languages với intelligent enhancements"""
    print_section("DEMO 4: Intelligent Supported Languages")
    
    print("🔍 Testing với intelligent workflow...")
    intelligent_result = get_supported_languages(intelligent=True)
    
    if intelligent_result.get("status") == "success":
        total = intelligent_result.get("total_languages", 0)
        popular = intelligent_result.get("popular_languages", [])
        print(f"📊 Total Languages: {total}")
        print(f"⭐ Popular Languages: {', '.join(popular[:10])}")
        
        # Show workflow metadata
        format_result(intelligent_result)
    else:
        print("❌ Failed to get languages")

def demo_code_structure_analysis():
    """Demo analyze_code_structure với intelligent features"""
    print_section("DEMO 5: Intelligent Code Structure Analysis")
    
    sample_code = """
class SecurityManager:
    def __init__(self):
        self.users = {}
    
    def authenticate(self, username, password):
        if username in self.users:
            return self.users[username] == password
        return False
    
    def add_user(self, username, password):
        self.users[username] = password  # Plain text storage!
"""
    
    print("🔍 Testing với intelligent workflow...")
    intelligent_result = analyze_code_structure(sample_code, "python", intelligent=True)
    format_result(intelligent_result)

def demo_rule_schema():
    """Demo get_semgrep_rule_schema với intelligent enhancements"""
    print_section("DEMO 6: Intelligent Rule Schema")
    
    print("🔍 Testing với intelligent workflow...")
    intelligent_result = get_semgrep_rule_schema(intelligent=True)
    
    if intelligent_result.get("status") == "success":
        print("✅ Rule schema retrieved successfully")
        format_result(intelligent_result)
    else:
        print("❌ Failed to get rule schema")

def demo_project_architecture():
    """Demo analyze_project_architecture với intelligent analysis"""
    print_section("DEMO 7: Intelligent Project Architecture Analysis")
    
    # Use current project as example
    project_path = "."
    
    print("🔍 Testing với intelligent workflow...")
    intelligent_result = analyze_project_architecture(project_path, intelligent=True)
    
    if intelligent_result.get("status") == "success":
        languages = intelligent_result.get("languages_detected", [])
        frameworks = intelligent_result.get("frameworks_detected", [])
        total_files = intelligent_result.get("total_files_analyzed", 0)
        
        print(f"📁 Total Files: {total_files}")
        print(f"🌍 Languages: {', '.join(languages[:5])}")
        print(f"🏗️ Frameworks: {', '.join(frameworks[:3])}")
        
        format_result(intelligent_result)
    else:
        print("❌ Failed to analyze project architecture")

def run_performance_comparison():
    """So sánh performance giữa intelligent và traditional workflows"""
    print_section("PERFORMANCE COMPARISON")
    
    import time
    
    test_code = "import os; os.system('ls')"
    
    # Test intelligent workflow
    start_time = time.time()
    intelligent_result = quick_security_check(test_code, "python", intelligent=True)
    intelligent_time = time.time() - start_time
    
    # Test traditional workflow
    start_time = time.time()
    traditional_result = quick_security_check(test_code, "python", intelligent=False)
    traditional_time = time.time() - start_time
    
    print(f"⏱️ Performance Results:")
    print(f"   • Intelligent Workflow: {intelligent_time:.3f}s")
    print(f"   • Traditional Workflow: {traditional_time:.3f}s")
    print(f"   • Intelligence Overhead: {(intelligent_time - traditional_time):.3f}s")
    
    # Quality comparison
    intel_findings = intelligent_result.get("total_findings", 0)
    trad_findings = traditional_result.get("total_findings", 0)
    
    print(f"🎯 Quality Results:")
    print(f"   • Intelligent Findings: {intel_findings}")
    print(f"   • Traditional Findings: {trad_findings}")
    
    # Check for intelligent enhancements
    intel_metadata = intelligent_result.get("workflow_metadata", {})
    if intel_metadata.get("workflow_type") == "sequential_intelligent":
        print("✅ Intelligent enhancements successfully applied")
    else:
        print("⚠️ Intelligent enhancements not detected")

def main():
    """Main demo function"""
    print_banner()
    
    print("\n🎯 Demo Objectives:")
    print("• Showcase ADK Sequential Workflow Agents")
    print("• Compare intelligent vs traditional tool execution")
    print("• Demonstrate context analysis, optimization, and enhanced execution")
    print("• Show workflow metadata and intelligence features")
    
    try:
        # Run all demos
        demo_scan_code_files()
        demo_quick_security_check()
        demo_custom_rule_scan()
        demo_supported_languages()
        demo_code_structure_analysis()
        demo_rule_schema()
        demo_project_architecture()
        
        # Performance comparison
        run_performance_comparison()
        
        print_section("DEMO COMPLETED SUCCESSFULLY")
        print("🎉 All intelligent workflows tested successfully!")
        print("📚 ADK Sequential Workflow Agents implementation complete")
        
    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 