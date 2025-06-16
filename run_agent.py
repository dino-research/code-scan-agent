#!/usr/bin/env python3
"""
Simple script để chạy Code Scan Agent
"""
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from code_scan_agent.config import get_config
from code_scan_agent.agent import (
    scan_code_directory,
    scan_code_files, 
    quick_security_check,
    get_supported_languages,
    analyze_code_structure
)

def print_banner():
    """In banner cho Code Scan Agent"""
    print("=" * 60)
    print("🔍 CODE SCAN AGENT")
    print("Powered by Semgrep MCP & Google ADK")
    print("=" * 60)

def show_menu():
    """Hiển thị menu lựa chọn"""
    print("\n📋 Chọn chức năng:")
    print("1. 📁 Scan thư mục")
    print("2. 📄 Scan file cụ thể")
    print("3. 🔍 Quick security check (paste code)")
    print("4. 🌍 Xem ngôn ngữ được hỗ trợ")
    print("5. 🚪 Thoát")
    return input("\nLựa chọn (1-5): ").strip()

def scan_directory_interactive():
    """Scan thư mục tương tác"""
    path = input("📁 Nhập đường dẫn thư mục cần scan: ").strip()
    if not path:
        print("❌ Vui lòng nhập đường dẫn!")
        return
    
    print(f"\n🔍 Đang scan thư mục: {path}")
    print("⏳ Vui lòng đợi...")
    
    result = scan_code_directory(path)
    
    if result["status"] == "success":
        if result.get("total_findings", 0) > 0:
            print(f"\n🚨 {result['summary']}")
            
            severity = result.get("severity_breakdown", {})
            if severity:
                print(f"📊 Phân tích theo mức độ:")
                for level, count in severity.items():
                    print(f"   • {level}: {count}")
            
            findings = result.get("detailed_results", [])
            if findings:
                print(f"\n📋 Chi tiết vấn đề (hiển thị tối đa 5):")
                for i, finding in enumerate(findings[:5], 1):
                    rule_id = finding.get("check_id", "unknown")
                    message = finding.get("extra", {}).get("message", "No message")
                    file_path = finding.get("path", "unknown file")
                    line = finding.get("start", {}).get("line", "?")
                    
                    print(f"\n   {i}. 🔴 {rule_id}")
                    print(f"      📁 File: {file_path}:{line}")
                    print(f"      💬 {message}")
        else:
            print(f"\n✅ {result['summary']}")
    else:
        print(f"\n❌ Lỗi: {result.get('error_message', 'Unknown error')}")

def scan_files_interactive():
    """Scan files tương tác"""
    files_input = input("📄 Nhập đường dẫn file(s) cần scan (cách nhau bằng dấu phẩy): ").strip()
    if not files_input:
        print("❌ Vui lòng nhập đường dẫn file!")
        return
    
    file_paths = [f.strip() for f in files_input.split(",")]
    
    print(f"\n🔍 Đang scan {len(file_paths)} file(s)")
    print("⏳ Vui lòng đợi...")
    
    result = scan_code_files(file_paths)
    
    if result["status"] == "success":
        print(f"\n✅ Scan hoàn tất!")
        print(f"📊 Đã scan {result['files_scanned']} file(s)")
        
        scan_result = result.get("result", {})
        if "content" in scan_result:
            findings = scan_result["content"]
            if isinstance(findings, list) and findings:
                print(f"🚨 Tìm thấy {len(findings)} vấn đề!")
                
                for i, finding in enumerate(findings[:3], 1):
                    rule_id = finding.get("check_id", "unknown")
                    message = finding.get("extra", {}).get("message", "No message")
                    print(f"   {i}. {rule_id}: {message}")
            else:
                print("✅ Không tìm thấy vấn đề bảo mật!")
    else:
        print(f"\n❌ Lỗi: {result.get('error_message', 'Unknown error')}")

def quick_check_interactive():
    """Quick security check tương tác"""
    print("🔍 Quick Security Check")
    print("Paste code của bạn (nhấn Enter 2 lần để kết thúc):")
    
    code_lines = []
    empty_count = 0
    
    while True:
        line = input()
        if line == "":
            empty_count += 1
            if empty_count >= 2:
                break
        else:
            empty_count = 0
        code_lines.append(line)
    
    if not code_lines or not any(line.strip() for line in code_lines):
        print("❌ Không có code để scan!")
        return
    
    code_content = "\n".join(code_lines)
    language = input("\n🌍 Nhập ngôn ngữ (python/javascript/java/...): ").strip() or "python"
    
    print(f"\n🔍 Đang scan code {language}")
    print("⏳ Vui lòng đợi...")
    
    result = quick_security_check(code_content, language)
    
    if result["status"] == "success":
        scan_result = result.get("result", {})
        if "content" in scan_result:
            findings = scan_result["content"]
            if isinstance(findings, list) and findings:
                print(f"\n🚨 Tìm thấy {len(findings)} vấn đề bảo mật!")
                
                for i, finding in enumerate(findings, 1):
                    rule_id = finding.get("check_id", "unknown")
                    message = finding.get("extra", {}).get("message", "No message")
                    severity = finding.get("extra", {}).get("severity", "unknown")
                    
                    print(f"\n   {i}. 🔴 {rule_id} ({severity})")
                    print(f"      💬 {message}")
                    
                    # Show code snippet if available
                    if "start" in finding and "end" in finding:
                        start_line = finding["start"].get("line", 1)
                        end_line = finding["end"].get("line", start_line)
                        print(f"      📍 Dòng {start_line}-{end_line}")
            else:
                print("\n✅ Không tìm thấy vấn đề bảo mật!")
    else:
        print(f"\n❌ Lỗi: {result.get('error_message', 'Unknown error')}")

def show_supported_languages():
    """Hiển thị ngôn ngữ được hỗ trợ"""
    print("\n🌍 Đang lấy danh sách ngôn ngữ được hỗ trợ...")
    
    result = get_supported_languages()
    
    if result["status"] == "success":
        languages = result.get("supported_languages", [])
        if languages and isinstance(languages, list):
            # Parse the response - it seems to be in a different format
            if len(languages) > 0 and isinstance(languages[0], dict):
                lang_text = languages[0].get("text", "")
                if "supported languages are:" in lang_text:
                    lang_list = lang_text.split("supported languages are:")[1].strip()
                    lang_items = [lang.strip() for lang in lang_list.split(",")]
                    
                    print(f"\n📋 Semgrep hỗ trợ {len(lang_items)} ngôn ngữ:")
                    
                    # Group by first letter for better display
                    grouped = {}
                    for lang in sorted(lang_items):
                        first_char = lang[0].upper()
                        if first_char not in grouped:
                            grouped[first_char] = []
                        grouped[first_char].append(lang)
                    
                    for letter in sorted(grouped.keys()):
                        print(f"\n   {letter}: {', '.join(grouped[letter])}")
                else:
                    print(f"✅ Tổng cộng: {len(languages)} ngôn ngữ")
                    print("   Sample:", languages[:10])
            else:
                print(f"✅ Tổng cộng: {len(languages)} ngôn ngữ")
                print("   Sample:", languages[:10])
        else:
            print("⚠️  Không có thông tin ngôn ngữ")
    else:
        print(f"❌ Lỗi: {result.get('error_message', 'Unknown error')}")

def main():
    """Hàm chính"""
    print_banner()
    
    # Kiểm tra cấu hình
    config = get_config()
    if not config.validate():
        print("❌ Cấu hình không hợp lệ!")
        print("🔧 Vui lòng kiểm tra file .env")
        return 1
    
    print("✅ Cấu hình hợp lệ!")
    print("🚀 Code Scan Agent sẵn sàng!")
    
    while True:
        try:
            choice = show_menu()
            
            if choice == "1":
                scan_directory_interactive()
            elif choice == "2":
                scan_files_interactive() 
            elif choice == "3":
                quick_check_interactive()
            elif choice == "4":
                show_supported_languages()
            elif choice == "5":
                print("\n👋 Tạm biệt!")
                break
            else:
                print("❌ Lựa chọn không hợp lệ!")
            
            input("\nNhấn Enter để tiếp tục...")
            
        except KeyboardInterrupt:
            print("\n\n👋 Tạm biệt!")
            break
        except Exception as e:
            print(f"\n❌ Lỗi: {e}")
            input("Nhấn Enter để tiếp tục...")
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 