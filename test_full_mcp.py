#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from code_scan_agent.semgrep_client import SemgrepSyncClient
from pathlib import Path

def test_full_mcp():
    print("=== Test Full MCP với All Examples ===")
    
    # Read all files from examples/
    code_files = []
    for file_path in Path('examples/').glob('*.py'):
        try:
            content = file_path.read_text()
            code_files.append({
                "filename": file_path.name,
                "content": content
            })
            print(f"📄 Added {file_path.name} ({len(content)} chars)")
        except Exception as e:
            print(f"❌ Failed to read {file_path}: {e}")
    
    if not code_files:
        print("❌ No files found!")
        return 0
    
    client = None
    try:
        client = SemgrepSyncClient(timeout=30)
        print("🚀 Starting client...")
        client.start_server()
        
        # Test with different configs and count total unique findings
        configs = [
            ('auto', 'Auto configuration'),
            ('p/security-audit', 'Security audit rules'),
            ('p/owasp-top-ten', 'OWASP Top 10 rules'),
            ('r/python.lang.security', 'Python security rules')
        ]
        
        all_findings = set()  # Track unique findings
        max_findings = 0
        best_config = None
        
        for config, description in configs:
            print(f"\n🔍 Testing {description} ({config})...")
            
            try:
                result = client.scan_code_files(code_files, config=config)
                
                if isinstance(result, dict) and 'results' in result:
                    findings = result['results']
                    findings_count = len(findings)
                    print(f"   🎯 Found {findings_count} findings")
                    
                    if findings_count > max_findings:
                        max_findings = findings_count
                        best_config = config
                    
                    # Track unique findings by check_id + path + line
                    for finding in findings:
                        check_id = finding.get('check_id', 'unknown')
                        path = finding.get('path', 'unknown')
                        line = finding.get('start', {}).get('line', 0)
                        unique_key = f"{check_id}:{path}:{line}"
                        all_findings.add(unique_key)
                    
                    # Show top findings for best performing config
                    if config == 'auto' and findings:
                        print("   Top 5 findings:")
                        for i, finding in enumerate(findings[:5], 1):
                            rule_id = finding.get('check_id', 'Unknown')
                            file_name = finding.get('path', 'Unknown')
                            line_num = finding.get('start', {}).get('line', '?')
                            message = finding.get('extra', {}).get('message', 'No message')
                            print(f"     {i}. {rule_id} in {file_name}:{line_num}")
                            print(f"        {message[:80]}...")
                
                elif isinstance(result, dict) and 'status' in result:
                    print(f"   📊 Status: {result['status']}")
                    if result.get('status') == 'error':
                        print(f"   ❌ Error: {result.get('message', 'No message')}")
                else:
                    print(f"   ❌ Unexpected result format: {type(result)}")
                    
            except Exception as e:
                print(f"   ❌ Error with {config}: {e}")
        
        print(f"\n📊 SUMMARY:")
        print(f"   • Max findings in single config: {max_findings} (using {best_config})")
        print(f"   • Total unique findings across all configs: {len(all_findings)}")
        print(f"   • Target (Semgrep Direct): 18 findings")
        
        success_ratio = max_findings / 18 if max_findings > 0 else 0
        print(f"   • Success ratio: {success_ratio:.1%}")
        
        return max_findings
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return 0
    finally:
        if client:
            client.stop_server()

if __name__ == "__main__":
    findings_count = test_full_mcp()
    print(f"\n🎯 FINAL RESULT: {findings_count} findings detected by MCP")
    print(f"🎯 TARGET: 18 findings by Semgrep Direct")
    
    if findings_count >= 15:
        print("🎉 EXCELLENT: MCP achieved >= 83% of target!")
    elif findings_count >= 10:
        print("✅ GOOD: MCP achieved >= 56% of target!")
    elif findings_count >= 5:
        print("⚡ PARTIAL: MCP working but needs improvement")
    elif findings_count > 0:
        print("🔧 WORKING: MCP basic functionality confirmed")
    else:
        print("❌ FAILED: No findings detected") 