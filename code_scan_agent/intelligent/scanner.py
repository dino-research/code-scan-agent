"""
Intelligent Code Scanner

Sử dụng Sequential Agent Pattern để triển khai intelligent scanning:
1. Rule Analysis Agent - Phân tích project và lựa chọn rules
2. Code Pattern Agent - Phân tích patterns và xác định scan priorities
3. Optimized Security Scan Agent - Thực hiện scan tối ưu
"""

import logging
from pathlib import Path
from typing import Dict, List, Any, Optional

try:
    from google.adk.agents import Agent
except ImportError:
    from .agents import Agent

logger = logging.getLogger(__name__)


class RuleAnalysisAgent(Agent):
    """
    Agent phân tích project để xác định rules Semgrep cần thiết
    """
    
    def __init__(self):
        super().__init__(name="RuleAnalysisAgent")
    
    def analyze_project_rules(self, directory_path: str) -> Dict[str, Any]:
        """
        Phân tích project để xác định rules cần thiết
        
        Args:
            directory_path: Đường dẫn thư mục project
            
        Returns:
            Dict chứa recommended rules và rationale
        """
        try:
            project_path = Path(directory_path)
            if not project_path.exists() or not project_path.is_dir():
                raise ValueError(f"Invalid directory: {directory_path}")
            
            # Phân tích file types và languages
            languages = self._detect_languages(project_path)
            frameworks = self._detect_frameworks(project_path)
            security_contexts = self._analyze_security_contexts(project_path)
            
            # Xác định rules dựa trên phân tích
            recommended_rules = self._determine_rules(languages, frameworks, security_contexts)
            
            return {
                "status": "success",
                "analysis": {
                    "languages_detected": languages,
                    "frameworks_detected": frameworks,
                    "security_contexts": security_contexts,
                    "recommended_rules": recommended_rules,
                    "rule_rationale": self._explain_rule_selection(recommended_rules, languages, frameworks)
                }
            }
            
        except Exception as e:
            logger.error(f"Rule analysis failed: {e}")
            return {
                "status": "error",
                "error": str(e),
                "fallback_rules": ["auto"]  # Fallback to auto rules
            }
    
    def _detect_languages(self, project_path: Path) -> List[str]:
        """Phát hiện ngôn ngữ lập trình trong project"""
        from collections import Counter
        
        language_extensions = {
            'python': ['.py', '.pyx', '.pyi'],
            'javascript': ['.js', '.mjs'],
            'typescript': ['.ts', '.tsx'],
            'java': ['.java'],
            'c': ['.c', '.h'],
            'cpp': ['.cpp', '.cc', '.cxx', '.hpp'],
            'csharp': ['.cs'],
            'php': ['.php', '.phtml'],
            'ruby': ['.rb', '.rake'],
            'go': ['.go'],
            'rust': ['.rs'],
            'swift': ['.swift'],
            'kotlin': ['.kt', '.kts'],
            'scala': ['.scala'],
            'dart': ['.dart'],
            'r': ['.r', '.R']
        }
        
        detected_languages = set()
        file_count = Counter()
        
        # Quét files trong project
        for file_path in project_path.rglob('*'):
            if file_path.is_file():
                suffix = file_path.suffix.lower()
                for lang, extensions in language_extensions.items():
                    if suffix in extensions:
                        detected_languages.add(lang)
                        file_count[lang] += 1
        
        # Sort by frequency
        sorted_languages = sorted(detected_languages, key=lambda x: file_count[x], reverse=True)
        
        logger.info(f"Detected languages: {sorted_languages}")
        return sorted_languages
    
    def _detect_frameworks(self, project_path: Path) -> List[str]:
        """Phát hiện frameworks và dependencies"""
        frameworks = set()
        
        # Check common config files
        config_indicators = {
            'package.json': ['react', 'vue', 'angular', 'express', 'nextjs'],
            'requirements.txt': ['django', 'flask', 'fastapi', 'pyramid'],
            'Gemfile': ['rails', 'sinatra'],
            'pom.xml': ['spring', 'struts'],
            'build.gradle': ['spring', 'android'],
            'Cargo.toml': ['actix', 'rocket'],
            'composer.json': ['laravel', 'symfony']
        }
        
        for config_file, framework_list in config_indicators.items():
            config_path = project_path / config_file
            if config_path.exists():
                try:
                    content = config_path.read_text(encoding='utf-8', errors='ignore').lower()
                    for framework in framework_list:
                        if framework in content:
                            frameworks.add(framework)
                except Exception as e:
                    logger.warning(f"Could not read {config_file}: {e}")
        
        return list(frameworks)
    
    def _analyze_security_contexts(self, project_path: Path) -> List[str]:
        """Phân tích contexts bảo mật trong project"""
        security_contexts = set()
        
        # Indicators for different security contexts
        context_indicators = {
            'web_app': ['http', 'https', 'url', 'request', 'response', 'session'],
            'database': ['sql', 'database', 'db', 'query', 'connect'],
            'api': ['api', 'rest', 'graphql', 'endpoint'],
            'crypto': ['encrypt', 'decrypt', 'hash', 'cipher', 'key'],
            'auth': ['auth', 'login', 'password', 'token', 'jwt'],
            'file_ops': ['file', 'read', 'write', 'upload', 'download']
        }
        
        # Sample a few files for quick analysis
        sample_files = []
        for ext in ['.py', '.js', '.java', '.php', '.rb']:
            sample_files.extend(list(project_path.rglob(f'*{ext}'))[:5])
        
        for file_path in sample_files[:20]:  # Limit to 20 files for performance
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore').lower()
                for context, indicators in context_indicators.items():
                    if any(indicator in content for indicator in indicators):
                        security_contexts.add(context)
            except Exception:
                continue
        
        return list(security_contexts)
    
    def _determine_rules(self, languages: List[str], frameworks: List[str], contexts: List[str]) -> List[str]:
        """Xác định Semgrep rules dựa trên phân tích"""
        rules = set()
        
        # Always include 'auto' for comprehensive coverage
        rules.add("auto")
        
        # Base security rules
        rules.add("p/security-audit")
        rules.add("p/owasp-top-ten")  # Add OWASP by default
        
        # Language-specific rules
        language_rules = {
            'python': ['p/python'],
            'javascript': ['p/javascript'],
            'typescript': ['p/typescript'],
            'java': ['p/java'],
            'php': ['p/php'],
            'ruby': ['p/ruby'],
            'go': ['p/golang']
        }
        
        # Only add language rules for primary languages
        for lang in languages[:2]:  # Top 2 languages
            if lang in language_rules:
                rules.update(language_rules[lang])
        
        # Framework-specific rules
        framework_rules = {
            'django': ['p/django'],
            'flask': ['p/flask'],
            'react': ['p/react'],
            'vue': ['p/vue'],
            'spring': ['p/spring'],
            'laravel': ['p/laravel'],
            'rails': ['p/rails']
        }
        
        for framework in frameworks:
            if framework in framework_rules:
                rules.update(framework_rules[framework])
        
        return list(rules)
    
    def _explain_rule_selection(self, rules: List[str], languages: List[str], frameworks: List[str]) -> Dict[str, str]:
        """Generate explanations for rule selection"""
        explanations = {}
        
        for rule in rules:
            if rule == "auto":
                explanations[rule] = "Automatic rule detection for comprehensive scanning"
            elif rule == "p/security-audit":
                explanations[rule] = "Security audit rules for vulnerability detection"
            elif rule == "p/owasp-top-ten":
                explanations[rule] = "OWASP Top 10 vulnerability detection"
            elif rule.startswith("p/") and rule[2:] in languages:
                lang = rule[2:]
                explanations[rule] = f"Language-specific rules for {lang}"
            elif rule.startswith("p/") and rule[2:] in frameworks:
                framework = rule[2:]
                explanations[rule] = f"Framework-specific rules for {framework}"
                
        return explanations


class CodePatternAgent(Agent):
    """
    Agent phân tích code patterns để xác định scan priorities
    """
    
    def __init__(self):
        super().__init__(name="CodePatternAgent")
    
    def analyze_code_patterns(self, directory_path: str, languages: List[str]) -> Dict[str, Any]:
        """
        Phân tích code patterns để xác định scan priorities
        
        Args:
            directory_path: Đường dẫn thư mục project
            languages: Danh sách ngôn ngữ được phát hiện
            
        Returns:
            Dict chứa pattern analysis và scan priorities
        """
        try:
            project_path = Path(directory_path)
            if not project_path.exists() or not project_path.is_dir():
                raise ValueError(f"Invalid directory: {directory_path}")
            
            # Phân tích file structure
            file_analysis = self._analyze_file_structure(project_path)
            
            # Phân tích code complexity
            complexity_analysis = self._analyze_complexity(project_path, languages)
            
            # Xác định risk patterns
            risk_patterns = self._identify_risk_patterns(project_path, languages)
            
            # Xác định scan priorities
            scan_priorities = self._create_scan_priorities(file_analysis, risk_patterns)
            
            # Tạo optimization suggestions
            optimization_suggestions = self._get_optimization_suggestions(file_analysis, risk_patterns)
            
            return {
                "status": "success",
                "pattern_analysis": {
                    "file_structure": file_analysis,
                    "complexity_metrics": complexity_analysis,
                    "risk_patterns": risk_patterns,
                    "scan_priorities": scan_priorities,
                    "optimization_suggestions": optimization_suggestions
                }
            }
            
        except Exception as e:
            logger.error(f"Code pattern analysis failed: {e}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    def _analyze_file_structure(self, project_path: Path) -> Dict[str, Any]:
        """Phân tích cấu trúc file của project"""
        import os
        
        total_files = 0
        size_bytes = 0
        file_extensions = {}
        
        for root, _, files in os.walk(project_path):
            for file in files:
                # Skip hidden files and directories
                if file.startswith('.') or '/.git/' in root:
                    continue
                
                file_path = Path(os.path.join(root, file))
                total_files += 1
                
                # Count file extensions
                ext = file_path.suffix.lower()
                if ext:
                    file_extensions[ext] = file_extensions.get(ext, 0) + 1
                
                # Get file size
                try:
                    size_bytes += file_path.stat().st_size
                except Exception:
                    pass
        
        # Sort extensions by frequency
        sorted_extensions = sorted(file_extensions.items(), key=lambda x: x[1], reverse=True)
        
        return {
            "total_files": total_files,
            "total_size_mb": round(size_bytes / (1024 * 1024), 2),
            "file_extensions": dict(sorted_extensions[:10]),  # Top 10 extensions
            "project_size": "large" if total_files > 1000 else "medium" if total_files > 100 else "small"
        }
    
    def _create_scan_priorities(self, file_analysis: Dict, risk_patterns: List[Dict]) -> Dict[str, Any]:
        """Create scan priorities based on file analysis and risk patterns"""
        # Calculate overall priority
        priority_level = "medium"  # Default
        
        # Adjust based on project size
        if file_analysis.get("project_size") == "large":
            priority_level = "high"
        elif file_analysis.get("project_size") == "small":
            priority_level = "low"
        
        # Adjust based on risk patterns
        high_risk_count = sum(1 for pattern in risk_patterns if pattern.get("severity") == "high")
        if high_risk_count > 3:
            priority_level = "high"
        
        # Determine scan approach
        scan_approach = self._get_scan_approach(priority_level, file_analysis)
        
        return {
            "priority_level": priority_level,
            "scan_approach": scan_approach,
            "high_risk_patterns": high_risk_count,
            "targeted_files": [pattern.get("file_pattern", "") for pattern in risk_patterns[:5]]
        }
    
    def _get_scan_approach(self, priority_level: str, file_analysis: Dict) -> str:
        """Determine scan approach based on priority level"""
        if priority_level == "high":
            return "comprehensive"
        elif priority_level == "medium":
            return "targeted"
        else:
            return "quick"


class OptimizedSecurityScanAgent(Agent):
    """
    Agent thực hiện security scanning với optimization
    """
    
    def __init__(self):
        super().__init__(name="OptimizedSecurityScanAgent")
    
    def perform_optimized_scan(self, directory_path: str, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Thực hiện security scan với optimization
        
        Args:
            directory_path: Đường dẫn thư mục cần scan
            analysis_results: Kết quả phân tích từ rule_analysis và pattern_analysis
            
        Returns:
            Dict chứa scan results và intelligence metadata
        """
        try:
            rule_analysis = analysis_results.get("rule_analysis", {})
            pattern_analysis = analysis_results.get("pattern_analysis", {})
            
            # Prepare scan configuration
            rules = rule_analysis.get("analysis", {}).get("recommended_rules", ["auto"])
            scan_priority = pattern_analysis.get("pattern_analysis", {}).get("scan_priorities", {})
            
            config = self._prepare_scan_config(rules, scan_priority)
            
            # Get client
            try:
                from ..semgrep_client import SemgrepSyncClient
                client = SemgrepSyncClient()
            except Exception as e:
                logger.error(f"Failed to initialize semgrep client: {e}")
                return self._fallback_scan(directory_path)
            
            # Execute scan based on approach
            scan_approach = scan_priority.get("scan_approach", "comprehensive")
            
            if scan_approach == "comprehensive":
                results = self._comprehensive_scan(client, directory_path, config)
            elif scan_approach == "targeted":
                results = self._targeted_scan(client, directory_path, config)
            else:
                results = self._quick_scan(client, directory_path, config)
            
            # Post-process results with analysis context
            enhanced_results = self._post_process_results(results, {
                "rule_analysis": rule_analysis,
                "pattern_analysis": pattern_analysis
            })
            
            return enhanced_results
            
        except Exception as e:
            logger.error(f"Optimized security scan failed: {e}")
            return self._fallback_scan(directory_path)
    
    def _prepare_scan_config(self, rules: List[str], scan_priority: Dict) -> Dict[str, Any]:
        """Prepare scan configuration based on rules and priority"""
        config = {
            "rules": rules,
            "config_string": self._build_config_string(rules),
            "priority_level": scan_priority.get("priority_level", "medium"),
            "targeted_files": scan_priority.get("targeted_files", [])
        }
        return config
    
    def _build_config_string(self, rules: List[str]) -> str:
        """Build config string from rules list"""
        if not rules or "auto" in rules:
            return "auto"
        
        # Convert rules list to comma-separated string
        return ",".join(rules)
    
    def _comprehensive_scan(self, client, directory_path: str, config: Dict) -> Dict[str, Any]:
        """Perform comprehensive scan with all rules"""
        return client.scan_directory(directory_path, config.get("config_string"))
    
    def _targeted_scan(self, client, directory_path: str, config: Dict) -> Dict[str, Any]:
        """Perform targeted scan focusing on high-risk areas"""
        return client.scan_directory(directory_path, config.get("config_string"))
    
    def _quick_scan(self, client, directory_path: str, config: Dict) -> Dict[str, Any]:
        """Perform quick scan with minimal rule set"""
        return client.scan_directory(directory_path, "p/security-audit")
    
    def _post_process_results(self, results: Dict[str, Any], analysis_context: Dict) -> Dict[str, Any]:
        """Post-process results with analysis context"""
        if not isinstance(results, dict):
            return {"status": "error", "error": "Invalid scan results"}
        
        # Extract findings from the raw results
        findings = []
        content_list = results.get("content", [])
        
        if content_list and len(content_list) > 0:
            first_content = content_list[0]
            if isinstance(first_content, dict) and "text" in first_content:
                try:
                    import json
                    text_content = first_content.get("text", "")
                    if text_content.strip():
                        parsed_data = json.loads(text_content)
                        findings = parsed_data.get("results", [])
                except json.JSONDecodeError:
                    findings = []
        
        # Enhance findings with context
        enhanced_findings = self._enhance_findings_with_context(findings, analysis_context)
        
        # Create final result
        return {
            "status": "success",
            "total_findings": len(enhanced_findings),
            "findings": enhanced_findings[:10],  # Top 10 findings
            "summary": f"Found {len(enhanced_findings)} issues with intelligent scanning",
            "intelligence_metadata": {
                "rules_used": analysis_context.get("rule_analysis", {}).get("analysis", {}).get("recommended_rules", []),
                "scan_approach": analysis_context.get("pattern_analysis", {}).get("pattern_analysis", {}).get("scan_priorities", {}).get("scan_approach", "standard")
            }
        }
    
    def _fallback_scan(self, directory_path: str) -> Dict[str, Any]:
        """Fallback to traditional scan if optimized scan fails"""
        logger.info("Using fallback traditional scan")
        try:
            from ..semgrep_client import SemgrepSyncClient
            client = SemgrepSyncClient()
            results = client.scan_directory(directory_path, "auto")
            
            return {
                "status": "success",
                "results": results,
                "note": "Used fallback traditional scan"
            }
        except Exception as e:
            logger.error(f"Fallback scan failed: {e}")
            return {
                "status": "error",
                "error": f"Scan failed: {str(e)}"
            }


class IntelligentCodeScanner:
    """
    Main Intelligent Code Scanner class
    Orchestrates the intelligent scanning workflow
    """
    
    def __init__(self):
        # Khởi tạo các sub-agents
        self.rule_analysis_agent = RuleAnalysisAgent()
        self.code_pattern_agent = CodePatternAgent()
        self.scan_agent = OptimizedSecurityScanAgent()
        
        logger.info("IntelligentCodeScanner initialized")
    
    def analyze_project(self, directory_path: str) -> Dict[str, Any]:
        """
        Phân tích project để xác định languages, frameworks và rules
        
        Args:
            directory_path: Đường dẫn thư mục cần phân tích
            
        Returns:
            Dict chứa kết quả phân tích
        """
        try:
            directory_path = str(Path(directory_path).resolve())
            
            # Step 1: Rule Analysis
            rule_results = self.rule_analysis_agent.analyze_project_rules(directory_path)
            
            if rule_results.get("status") != "success":
                return None
                
            analysis = rule_results.get("analysis", {})
            
            # Extract languages from rule analysis
            languages = analysis.get("languages_detected", [])
            
            # Step 2: Code Pattern Analysis
            pattern_results = self.code_pattern_agent.analyze_code_patterns(directory_path, languages)
            
            # Combine results
            result = {
                "languages_detected": analysis.get("languages_detected", []),
                "frameworks_detected": analysis.get("frameworks_detected", []),
                "recommended_rules": analysis.get("recommended_rules", []),
                "security_contexts": analysis.get("security_contexts", [])
            }
            
            # Add pattern analysis if successful
            if pattern_results.get("status") == "success":
                pattern_data = pattern_results.get("pattern_analysis", {})
                result.update({
                    "risk_patterns": pattern_data.get("risk_patterns", []),
                    "scan_priority": pattern_data.get("scan_priorities", {}).get("priority_level", "medium"),
                    "recommendations": self._generate_recommendations(rule_results, pattern_results, {})
                })
            
            return result
            
        except Exception as e:
            logger.error(f"Project analysis failed: {e}")
            return None
    
    def intelligent_scan_directory(self, directory_path: str) -> Dict[str, Any]:
        """
        Thực hiện intelligent scan trên một thư mục code
        
        Args:
            directory_path: Đường dẫn thư mục cần scan
            
        Returns:
            Dict chứa kết quả và metadata
        """
        try:
            directory_path = str(Path(directory_path).resolve())
            logger.info(f"Starting intelligent scan on {directory_path}")
            
            # Step 1: Rule Analysis
            logger.info("Step 1: Analyzing project to determine optimal rules...")
            rule_results = self.rule_analysis_agent.analyze_project_rules(directory_path)
            
            if rule_results.get("status") != "success":
                logger.warning("Rule analysis failed, falling back to traditional scan")
                return self._fallback_traditional_scan(directory_path)
            
            # Extract languages from rule analysis
            languages = rule_results.get("analysis", {}).get("languages_detected", [])
            
            # Step 2: Code Pattern Analysis
            logger.info("Step 2: Analyzing code patterns...")
            pattern_results = self.code_pattern_agent.analyze_code_patterns(directory_path, languages)
            
            if pattern_results.get("status") != "success":
                logger.warning("Pattern analysis failed, proceeding with default patterns")
                # Continue with partial results (rule analysis only)
            
            # Step 3: Optimized Security Scan
            logger.info("Step 3: Performing optimized security scan...")
            scan_results = self.scan_agent.perform_optimized_scan(directory_path, {
                "rule_analysis": rule_results,
                "pattern_analysis": pattern_results
            })
            
            # Create summary and format final results
            summary = self._create_scan_summary(rule_results, pattern_results, scan_results)
            recommendations = self._generate_recommendations(rule_results, pattern_results, scan_results)
            
            # Format final results
            final_results = self._format_intelligent_results(scan_results, directory_path)
            
            # Add summary and metadata
            final_results.update({
                "rule_analysis": rule_results,
                "pattern_analysis": pattern_results,
                "summary": summary,
                "recommendations": recommendations,
                "workflow_steps": {
                    "rule_analysis": rule_results.get("status") == "success",
                    "pattern_analysis": pattern_results.get("status") == "success", 
                    "optimized_scan": scan_results.get("status") == "success"
                },
                "optimal_scan_strategy": self._determine_optimal_strategy(rule_results, pattern_results)
            })
            
            logger.info("Intelligent scan completed successfully")
            return final_results
            
        except Exception as e:
            logger.error(f"Intelligent scan failed: {e}")
            return self._fallback_traditional_scan(directory_path)
    
    def _create_scan_summary(self, rule_results: Dict, pattern_results: Dict, scan_results: Dict) -> str:
        """Create summary of scan results"""
        languages = rule_results.get("analysis", {}).get("languages_detected", [])
        rules_used = rule_results.get("analysis", {}).get("recommended_rules", [])
        findings = scan_results.get("findings", [])
        
        return f"Intelligent scan completed for {', '.join(languages) if languages else 'unknown'} project. " \
               f"Used {len(rules_used)} rules and found {len(findings)} issues."
    
    def _generate_recommendations(self, rule_results: Dict, pattern_results: Dict, scan_results: Dict) -> List[str]:
        """Generate recommendations based on analysis and scan results"""
        recommendations = []
        
        # Add recommendations based on rule analysis
        languages = rule_results.get("analysis", {}).get("languages_detected", [])
        frameworks = rule_results.get("analysis", {}).get("frameworks_detected", [])
        security_contexts = rule_results.get("analysis", {}).get("security_contexts", [])
        
        if "web_app" in security_contexts:
            recommendations.append("Consider implementing Content Security Policy (CSP) for web applications")
            
        if "database" in security_contexts:
            recommendations.append("Use parameterized queries to prevent SQL injection")
            
        if "auth" in security_contexts:
            recommendations.append("Implement proper password hashing and salting")
            
        # Add language-specific recommendations
        if "python" in languages:
            recommendations.append("Use Python's built-in 'secrets' module instead of 'random' for security operations")
            
        if "javascript" in languages:
            recommendations.append("Validate and sanitize all user inputs to prevent XSS attacks")
            
        # Add framework-specific recommendations
        if "django" in frameworks:
            recommendations.append("Ensure Django's CSRF protection is enabled")
            
        if "react" in frameworks:
            recommendations.append("Use React's dangerouslySetInnerHTML carefully to avoid XSS")
            
        # Add general security recommendations
        recommendations.append("Regularly update dependencies to patch security vulnerabilities")
        recommendations.append("Implement proper error handling that doesn't expose sensitive information")
        
        return recommendations
    
    def _determine_optimal_strategy(self, rule_results: Dict, pattern_results: Dict) -> Dict[str, Any]:
        """Determine optimal scanning strategy based on analysis"""
        languages = rule_results.get("analysis", {}).get("languages_detected", [])
        scan_priorities = pattern_results.get("pattern_analysis", {}).get("scan_priorities", {})
        priority_level = scan_priorities.get("priority_level", "medium")
        
        strategies = {
            "high": {
                "recommended_approach": "comprehensive",
                "confidence_level": "high",
                "scan_priority": "high"
            },
            "medium": {
                "recommended_approach": "targeted",
                "confidence_level": "medium", 
                "scan_priority": "medium"
            },
            "low": {
                "recommended_approach": "quick",
                "confidence_level": "medium",
                "scan_priority": "low"
            }
        }
        
        return strategies.get(priority_level, strategies["medium"])
    
    def _format_intelligent_results(self, scan_results: Dict, directory_path: str) -> Dict[str, Any]:
        """Format final results from intelligent scan"""
        # If scan was successful, use its results
        if scan_results.get("status") == "success":
            return {
                "status": "success",
                "scan_type": "intelligent",
                "intelligent_features": True,
                "directory": directory_path,
                "findings": scan_results.get("findings", []),
                "total_findings": scan_results.get("total_findings", 0),
                "scan_summary": scan_results.get("summary", "Scan completed")
            }
        
        # Otherwise, return basic structure
        return {
            "status": "partial_success",
            "scan_type": "intelligent_partial",
            "intelligent_features": True,
            "directory": directory_path,
            "findings": [],
            "total_findings": 0,
            "scan_summary": "Partial scan completed"
        }
    
    def _fallback_traditional_scan(self, directory_path: str) -> Dict[str, Any]:
        """Fallback to traditional scan if intelligent scan fails"""
        logger.info("Using fallback traditional scan")
        try:
            from ..agent import scan_code_directory
            result = scan_code_directory(directory_path, intelligent=False)
            
            result.update({
                "scan_type": "traditional_fallback",
                "intelligent_features": False,
                "note": "Intelligent scan failed, used traditional scan instead"
            })
            
            return result
        except Exception as e:
            logger.error(f"Fallback scan failed: {e}")
            return {
                "status": "error",
                "error": f"Intelligent scan failed: {str(e)}"
            }


# Standalone function for external usage
def intelligent_scan_code_directory(directory_path: str) -> Dict[str, Any]:
    """
    Thực hiện intelligent scan cho thư mục code
    
    Args:
        directory_path: Đường dẫn thư mục cần scan
        
    Returns:
        Dict chứa kết quả và metadata
    """
    scanner = IntelligentCodeScanner()
    return scanner.intelligent_scan_directory(directory_path) 