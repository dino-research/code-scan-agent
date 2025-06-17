#!/usr/bin/env python3
"""
Demo: Intelligent Code Scanning với ADK Workflow Agents

Minh họa tính năng intelligent scanning mới với:
1. Rule Analysis Agent - Phân tích rules cần thiết
2. Code Pattern Agent - Phân tích code patterns
3. Optimized Security Scan Agent - Scan tối ưu

Để chạy demo: python demo_intelligent_scanning.py
"""

import sys
import time
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from code_scan_agent import scan_code_directory
from code_scan_agent.intelligent.scanner import IntelligentCodeScanner


def demo_intelligent_vs_traditional():
    """Demo so sánh intelligent scanning vs traditional scanning"""
    print("\n🤖 Demo: Intelligent vs Traditional Scanning")
    print("=" * 60)
    
    demo_directory = "examples"
    
    print(f"📁 Scanning directory: {demo_directory}")
    print("\n1️⃣ Traditional Scanning (config mặc định):")
    print("-" * 40)
    
    start_time = time.time()
    try:
        # Traditional scan với config cố định
        traditional_result = scan_code_directory(demo_directory, intelligent=False)
        traditional_time = time.time() - start_time
        print(f"✅ Traditional scan hoàn thành trong {traditional_time:.2f}s")
        print(f"📊 Kết quả: {'traditional'} scan")
        
    except Exception as e:
        print(f"❌ Traditional scan failed: {e}")
    
    print("\n2️⃣ Intelligent Scanning (với workflow agents):")
    print("-" * 50)
    
    start_time = time.time()
    try:
        # Intelligent scan với rule optimization
        intelligent_result = scan_code_directory(demo_directory, intelligent=True)
        intelligent_time = time.time() - start_time
        print(f"✅ Intelligent scan hoàn thành trong {intelligent_time:.2f}s")
        print(f"📊 Kết quả: {'intelligent'} scan")
        
        # Hiển thị intelligent features
        print("\n🧠 Intelligent Features:")
        print(f"   • Rule Analysis: ✅")
        print(f"   • Pattern Analysis: ✅") 
        print(f"   • Optimized Scan: ✅")
        
    except Exception as e:
        print(f"❌ Intelligent scan failed: {e}")


def demo_project_analysis():
    """Demo intelligent project analysis"""
    print("\n🔍 Demo: Intelligent Project Analysis")
    print("=" * 60)
    
    demo_directory = "examples"
    
    print(f"📁 Analyzing project: {demo_directory}")
    print("🔄 Running intelligent analysis...")
    
    try:
        # Chạy intelligent project analysis
        scanner = IntelligentCodeScanner()
        analysis_result = scanner.analyze_project(demo_directory)
        
        if analysis_result:
            print("✅ Project analysis hoàn thành!")
            
            # Hiển thị languages detected
            languages = analysis_result.get('languages_detected', [])
            frameworks = analysis_result.get('frameworks_detected', [])
            rules = analysis_result.get('recommended_rules', [])
            
            print(f"\n📋 Languages detected: {', '.join(languages) if languages else 'None'}")
            print(f"🚀 Frameworks detected: {', '.join(frameworks) if frameworks else 'None'}")
            print(f"⚙️ Recommended rules: {len(rules) if rules else 0} rules")
            
            # Hiển thị pattern analysis
            risk_patterns = analysis_result.get('risk_patterns', [])
            scan_priority = analysis_result.get('scan_priority', 'medium')
            
            print(f"\n🎯 Risk patterns found: {len(risk_patterns) if risk_patterns else 0}")
            print(f"📊 Scan priority: {scan_priority}")
            
            # Hiển thị recommendations
            recommendations = analysis_result.get('recommendations', [])
            if recommendations:
                print(f"\n📋 Recommendations ({len(recommendations)}):")
                for i, rec in enumerate(recommendations[:4], 1):
                    print(f"   {i}. {rec}")
        
        else:
            print(f"❌ Analysis failed: Unknown error")
            
    except Exception as e:
        print(f"❌ Analysis failed: {e}")


def demo_workflow_explanation():
    """Demo giải thích workflow của intelligent scanning"""
    print("\n📚 Demo: Intelligent Scanning Workflow")
    print("=" * 60)
    
    print("🔄 Quy trình Intelligent Scanning gồm 3 bước:")
    print()
    
    print("1️⃣ Rule Analysis Agent")
    print("   📋 Phân tích project structure")
    print("   🔍 Detect languages & frameworks")
    print("   ⚙️ Recommend optimal Semgrep rules")
    print("   💡 Explain rule selection rationale")
    print()
    
    print("2️⃣ Code Pattern Agent")
    print("   📊 Analyze file complexity")
    print("   🎯 Identify high-risk patterns")
    print("   📈 Calculate scan priorities")
    print("   🚀 Suggest optimization strategies")
    print()
    
    print("3️⃣ Optimized Security Scan Agent")
    print("   ⚡ Execute scan with optimized rules")
    print("   🎯 Apply priority-based approach")
    print("   📋 Enhance findings with context")
    print("   🔄 Fallback to traditional if needed")
    print()
    
    print("✨ Lợi ích của Intelligent Scanning:")
    print("   • Hiệu quả cao hơn với rules được tối ưu")
    print("   • Phát hiện được các patterns risk cao")
    print("   • Scan time ngắn hơn với targeted approach")
    print("   • Kết quả có context và recommendations")
    print("   • Tự động fallback khi gặp lỗi")


def demo_comparison_scenarios():
    """Demo các scenarios khác nhau"""
    print("\n📝 Demo: Scenarios So Sánh")
    print("=" * 60)
    
    scenarios = [
        {
            "name": "Python Web App (Django/Flask)",
            "description": "Multi-file Python project với web framework",
            "expected_intelligence": "Detect Python + web frameworks → recommend p/python, p/django/flask, p/owasp-top-ten"
        },
        {
            "name": "JavaScript Frontend (React)",
            "description": "Node.js project với React components",
            "expected_intelligence": "Detect JS + React → recommend p/javascript, p/react, p/typescript"
        },
        {
            "name": "Multi-language Project", 
            "description": "Project có Python, JavaScript, Java",
            "expected_intelligence": "Multi-language detection → comprehensive rules + priority-based scanning"
        },
        {
            "name": "Small Simple Project",
            "description": "Vài files Python đơn giản",
            "expected_intelligence": "Low complexity → quick scan với p/security-audit"
        }
    ]
    
    for i, scenario in enumerate(scenarios, 1):
        print(f"{i}️⃣ {scenario['name']}")
        print(f"   📝 {scenario['description']}")
        print(f"   🧠 Expected Intelligence: {scenario['expected_intelligence']}")
        print()
    
    print("💡 Intelligent scanning sẽ tự động:")
    print("   • Phát hiện project type")
    print("   • Chọn rules phù hợp")
    print("   • Tối ưu scan approach")
    print("   • Cung cấp context-aware results")


def main():
    """Main demo function"""
    print("🤖 Code Scan Agent - Intelligent Scanning Demo")
    print("=" * 70)
    print("📚 Demo tính năng Intelligent Scanning với ADK Workflow Agents")
    print("🔗 Dựa trên: https://google.github.io/adk-docs/agents/workflow-agents/")
    print()
    
    # Run demos
    demo_workflow_explanation()
    demo_comparison_scenarios()
    demo_project_analysis()
    demo_intelligent_vs_traditional()
    
    print("\n🎉 Demo hoàn thành!")
    print("\n📋 Để sử dụng intelligent scanning:")
    print("   • Mặc định: scan_code_directory(path) → intelligent mode")
    print("   • Traditional: scan_code_directory(path, intelligent=False)")
    print("   • Analysis only: IntelligentCodeScanner().analyze_project(path)")
    print()
    print("💡 Intelligent scanning sẽ tự động detect và optimize!")


if __name__ == "__main__":
    main() 