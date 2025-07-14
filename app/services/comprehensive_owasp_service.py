"""
Comprehensive OWASP Security Testing Framework Integration Service
Provides unified access to all OWASP testing guides and frameworks
"""

from app.services.owasp_service import OWASPService
from app.services.api_security_service import APISecurityService
from app.services.iot_security_service import IoTSecurityService
from app.services.asvs_service import ASVSService
# from app.services.cloud_security_service import CloudSecurityService

class ComprehensiveOWASPService:
    """Unified service for all OWASP security testing frameworks"""
    
    @staticmethod
    def get_all_frameworks():
        """Get list of all available OWASP testing frameworks"""
        return {
            'wstg': {
                'name': 'Web Security Testing Guide',
                'description': 'Comprehensive web application security testing methodology',
                'version': '4.2',
                'categories': ['Authentication', 'Authorization', 'Session Management', 'Input Validation', 'Error Handling', 'Cryptography', 'Business Logic', 'Client Side', 'Configuration']
            },
            'mstg': {
                'name': 'Mobile Security Testing Guide',
                'description': 'Mobile application security testing for iOS and Android',
                'version': '1.4',
                'categories': ['Platform Security', 'Data Storage', 'Cryptography', 'Authentication', 'Network Communication', 'Interaction', 'Code Quality']
            },
            'api_security': {
                'name': 'API Security Top 10',
                'description': 'Top 10 API security risks and testing methodologies',
                'version': '2023',
                'categories': ['Authorization', 'Authentication', 'Data Exposure', 'Rate Limiting', 'Injection', 'Mass Assignment', 'Security Misconfiguration', 'Inventory Management', 'Logging', 'Asset Management']
            },
            'iot_security': {
                'name': 'IoT Security Testing Guide (ISTG)',
                'description': 'Comprehensive IoT device security testing methodology',
                'version': '1.0',
                'categories': ['Processing Units', 'Memory Security', 'Firmware Security', 'Data Exchange Services', 'Internal Interfaces', 'Physical Interfaces', 'Wireless Interfaces', 'User Interfaces']
            },
            'asvs': {
                'name': 'Application Security Verification Standard',
                'description': 'Comprehensive application security verification requirements',
                'version': '5.0',
                'categories': ['Architecture & Design', 'Input Validation & Business Logic', 'Web Frontend Security', 'API & Web Service Security', 'File Handling', 'Authentication', 'Session Management', 'Authorization', 'Self-contained Tokens', 'OAuth & OIDC', 'Cryptography', 'Secure Communication', 'Configuration', 'Data Protection']
            },
            # 'cloud_security': {
            #     'name': 'Cloud Security Testing Guide',
            #     'description': 'Cloud security testing based on OWASP sources, industry best practices, and CIS benchmarks',
            #     'version': '1.0',
            #     'categories': ['Identity and Access Management', 'Data Protection', 'Network Security', 'Infrastructure Security', 'Monitoring and Logging', 'Application Security', 'Compliance and Governance', 'Disaster Recovery', 'CIS Benchmarks']
            # }
        }
    
    @staticmethod
    def fetch_framework_data(framework_name):
        """Fetch data for a specific framework"""
        try:
            if framework_name == 'wstg':
                return OWASPService.fetch_wstg_data()
            elif framework_name == 'mstg':
                return OWASPService.fetch_mstg_data()
            elif framework_name == 'api_security':
                return APISecurityService.fetch_api_security_data()
            elif framework_name == 'iot_security':
                return IoTSecurityService.fetch_iot_security_data()
            elif framework_name == 'asvs':
                return ASVSService.fetch_asvs_data()
            # elif framework_name == 'cloud_security':
            #     return CloudSecurityService.get_cloud_security_with_cis()
            else:
                raise ValueError(f"Unknown framework: {framework_name}")
        except Exception as e:
            print(f"Error fetching {framework_name} data: {e}")
            return []
    
    @staticmethod
    def get_comprehensive_checklist():
        """Get a comprehensive checklist combining all frameworks"""
        all_frameworks = ComprehensiveOWASPService.get_all_frameworks()
        comprehensive_data = {}
        
        for framework_key, framework_info in all_frameworks.items():
            try:
                framework_data = ComprehensiveOWASPService.fetch_framework_data(framework_key)
                if framework_data:
                    comprehensive_data[framework_key] = {
                        'info': framework_info,
                        'tests': framework_data,
                        'test_count': len(framework_data)
                    }
                    print(f"Loaded {len(framework_data)} tests from {framework_info['name']}")
            except Exception as e:
                print(f"Failed to load {framework_info['name']}: {e}")
                comprehensive_data[framework_key] = {
                    'info': framework_info,
                    'tests': [],
                    'test_count': 0,
                    'error': str(e)
                }
        
        return comprehensive_data
    
    @staticmethod
    def get_framework_by_application_type(app_type):
        """Get relevant frameworks based on application type"""
        framework_mapping = {
            'web': ['wstg', 'asvs', 'api_security'],
            'mobile': ['mstg', 'asvs', 'api_security'],
            'api': ['api_security', 'asvs', 'wstg'],
            'iot': ['iot_security', 'api_security', 'asvs'],
            'cloud': ['asvs', 'api_security', 'wstg'],  # cloud_security commented out
            'desktop': ['asvs', 'wstg'],
            'hybrid': ['wstg', 'mstg', 'api_security', 'asvs']
        }
        
        return framework_mapping.get(app_type.lower(), ['wstg', 'asvs'])
    
    @staticmethod
    def get_risk_based_testing_plan(app_type, risk_level='medium'):
        """Generate a risk-based testing plan"""
        relevant_frameworks = ComprehensiveOWASPService.get_framework_by_application_type(app_type)
        all_frameworks = ComprehensiveOWASPService.get_all_frameworks()
        
        testing_plan = {
            'application_type': app_type,
            'risk_level': risk_level,
            'frameworks': [],
            'total_tests': 0,
            'estimated_hours': 0
        }
        
        # Priority mapping based on risk level
        risk_priorities = {
            'low': ['asvs'],
            'medium': ['wstg', 'asvs'],
            'high': ['wstg', 'mstg', 'api_security', 'asvs', 'iot_security']  # cloud_security commented out
        }
        
        priority_frameworks = risk_priorities.get(risk_level, relevant_frameworks)
        selected_frameworks = [fw for fw in relevant_frameworks if fw in priority_frameworks]
        
        for framework_key in selected_frameworks:
            if framework_key in all_frameworks:
                framework_info = all_frameworks[framework_key]
                framework_data = ComprehensiveOWASPService.fetch_framework_data(framework_key)
                
                # Estimate testing hours based on framework and number of tests
                test_count = len(framework_data) if framework_data else 0
                hours_per_test = {
                    'wstg': 0.5,
                    'mstg': 0.75,
                    'api_security': 0.25,
                    'iot_security': 1.0,
                    'asvs': 0.5
                    # 'cloud_security': 0.75  # commented out
                }
                
                estimated_hours = test_count * hours_per_test.get(framework_key, 0.5)
                
                testing_plan['frameworks'].append({
                    'key': framework_key,
                    'name': framework_info['name'],
                    'test_count': test_count,
                    'estimated_hours': estimated_hours,
                    'priority': 'high' if framework_key in ['wstg', 'asvs'] else 'medium'
                })
                
                testing_plan['total_tests'] += test_count
                testing_plan['estimated_hours'] += estimated_hours
        
        return testing_plan
    
    @staticmethod
    def get_cache_status():
        """Get cache status for all frameworks"""
        try:
            from app.models import OWASPDataCache
            from app import db
            
            cache_status = {}
            frameworks = ComprehensiveOWASPService.get_all_frameworks()
            
            for framework_key in frameworks.keys():
                # Map framework keys to cache data types
                cache_type_mapping = {
                    'wstg': 'wstg',
                    'mstg': 'mstg',
                    'api_security': 'api_security',
                    'iot_security': 'iot_security',
                    'asvs': 'asvs'
                    # 'cloud_security': 'cloud_security'  # commented out
                }
                
                cache_type = cache_type_mapping.get(framework_key)
                if cache_type:
                    try:
                        cache_entry = OWASPDataCache.query.filter_by(data_type=cache_type).order_by(OWASPDataCache.last_updated.desc()).first()
                        if cache_entry:
                            cache_status[framework_key] = {
                                'last_updated': cache_entry.last_updated,
                                'data_source': cache_entry.data_source,
                                'test_count': cache_entry.test_count
                            }
                        else:
                            cache_status[framework_key] = {
                                'last_updated': None,
                                'data_source': 'none',
                                'test_count': 0
                            }
                    except Exception as e:
                        print(f"Error accessing cache for {framework_key}: {e}")
                        cache_status[framework_key] = {
                            'last_updated': None,
                            'data_source': 'error',
                            'test_count': 0
                        }
            
            return cache_status
        except Exception as e:
            print(f"Error getting cache status: {e}")
            # Return empty cache status if there's any error
            return {}
    
    @staticmethod
    def refresh_all_frameworks():
        """Refresh data for all frameworks"""
        results = {}
        frameworks = ComprehensiveOWASPService.get_all_frameworks()
        
        for framework_key, framework_info in frameworks.items():
            try:
                print(f"Refreshing {framework_info['name']}...")
                data = ComprehensiveOWASPService.fetch_framework_data(framework_key)
                results[framework_key] = {
                    'success': True,
                    'test_count': len(data) if data else 0,
                    'message': f"Successfully refreshed {len(data) if data else 0} tests"
                }
            except Exception as e:
                results[framework_key] = {
                    'success': False,
                    'test_count': 0,
                    'message': f"Failed to refresh: {str(e)}"
                }
        
        return results
    
    @staticmethod
    def get_testing_methodology(framework_key):
        """Get testing methodology for a specific framework"""
        methodologies = {
            'wstg': {
                'approach': 'Manual and automated web application testing',
                'tools': ['Burp Suite', 'OWASP ZAP', 'Nmap', 'SQLMap'],
                'phases': ['Information Gathering', 'Configuration Testing', 'Authentication Testing', 'Session Management Testing', 'Authorization Testing', 'Data Validation Testing', 'Error Handling', 'Cryptography', 'Business Logic Testing', 'Client Side Testing']
            },
            'mstg': {
                'approach': 'Mobile application security testing for iOS and Android',
                'tools': ['MobSF', 'Frida', 'Objection', 'APKTool', 'Class-dump'],
                'phases': ['Static Analysis', 'Dynamic Analysis', 'Runtime Analysis', 'Network Analysis', 'Platform Security', 'Code Quality']
            },
            'api_security': {
                'approach': 'API-specific security testing methodology',
                'tools': ['Postman', 'Burp Suite', 'OWASP ZAP', 'Insomnia', 'Newman'],
                'phases': ['API Discovery', 'Authentication Testing', 'Authorization Testing', 'Data Validation', 'Rate Limiting', 'Error Handling']
            },
            'iot_security': {
                'approach': 'Comprehensive IoT device security testing',
                'tools': ['Hardware analysis tools', 'Firmware analysis tools', 'Network scanners', 'Protocol analyzers'],
                'phases': ['Hardware Analysis', 'Firmware Analysis', 'Network Analysis', 'Radio Frequency Analysis', 'Cloud Backend Testing']
            },
            'asvs': {
                'approach': 'Verification-based security testing',
                'tools': ['Various security testing tools', 'Static analysis tools', 'Dynamic analysis tools'],
                'phases': ['Level 1 Basic Verification', 'Level 2 Standard Verification', 'Level 3 Advanced Verification']
            },
            # 'cloud_security': {
            #     'approach': 'Cloud infrastructure and application security testing',
            #     'tools': ['Cloud security scanners', 'IAM analyzers', 'Configuration assessment tools'],
            #     'phases': ['Identity & Access Testing', 'Data Protection Testing', 'Network Security Testing', 'Configuration Assessment', 'Monitoring Validation']
            # }
        }
        
        return methodologies.get(framework_key, {
            'approach': 'General security testing methodology',
            'tools': ['Security testing tools'],
            'phases': ['Planning', 'Testing', 'Reporting']
        })
    
    @staticmethod
    def get_how_to_test_guide(framework_key):
        """Get comprehensive 'how to test' guide for a specific framework"""
        guides = {
            'wstg': {
                'title': 'Web Security Testing Guide - How to Test',
                'overview': 'The OWASP Web Security Testing Guide provides a comprehensive methodology for testing web application security.',
                'prerequisites': [
                    'Understanding of web application architecture',
                    'Knowledge of HTTP/HTTPS protocols',
                    'Familiarity with web security concepts',
                    'Basic understanding of web technologies (HTML, JavaScript, SQL)'
                ],
                'setup': [
                    'Install a web proxy tool (Burp Suite, OWASP ZAP)',
                    'Set up a testing environment or lab',
                    'Configure browser proxy settings',
                    'Prepare testing tools and scripts'
                ],
                'methodology': [
                    '1. Information Gathering: Collect information about the target application',
                    '2. Configuration Testing: Test server and application configurations',
                    '3. Authentication Testing: Test authentication mechanisms',
                    '4. Session Management: Test session handling',
                    '5. Authorization Testing: Test access controls',
                    '6. Data Validation: Test input validation',
                    '7. Error Handling: Test error messages and exception handling',
                    '8. Cryptography: Test cryptographic implementations',
                    '9. Business Logic: Test application logic flaws',
                    '10. Client Side: Test client-side security'
                ],
                'tools': {
                    'Burp Suite': 'Comprehensive web application security testing platform',
                    'OWASP ZAP': 'Free security testing proxy',
                    'Nmap': 'Network discovery and security auditing',
                    'SQLMap': 'Automatic SQL injection tool',
                    'Nikto': 'Web server scanner'
                },
                'reporting': 'Document findings with evidence, impact assessment, and remediation recommendations'
            },
            'mstg': {
                'title': 'Mobile Security Testing Guide - How to Test',
                'overview': 'The OWASP Mobile Security Testing Guide provides methodology for testing mobile applications on iOS and Android.',
                'prerequisites': [
                    'Understanding of mobile application architecture',
                    'Knowledge of iOS/Android security models',
                    'Familiarity with mobile development',
                    'Basic reverse engineering skills'
                ],
                'setup': [
                    'Set up mobile testing environment (real devices/emulators)',
                    'Install mobile security testing tools',
                    'Configure proxy for mobile traffic interception',
                    'Prepare static and dynamic analysis tools'
                ],
                'methodology': [
                    '1. Static Analysis: Analyze application code and resources',
                    '2. Dynamic Analysis: Test runtime behavior',
                    '3. Network Analysis: Intercept and analyze network traffic',
                    '4. Platform Security: Test platform-specific security features',
                    '5. Code Quality: Assess code quality and security',
                    '6. Reverse Engineering: Analyze application internals'
                ],
                'tools': {
                    'MobSF': 'Mobile Security Framework for static and dynamic analysis',
                    'Frida': 'Dynamic instrumentation toolkit',
                    'Objection': 'Runtime mobile exploration toolkit',
                    'APKTool': 'Tool for reverse engineering Android APK files',
                    'Class-dump': 'Utility for examining Objective-C runtime information'
                },
                'reporting': 'Document mobile-specific security issues with platform details and remediation guidance'
            },
            'api_security': {
                'title': 'API Security Testing - How to Test',
                'overview': 'Testing methodology for REST, GraphQL, and other API security vulnerabilities.',
                'prerequisites': [
                    'Understanding of API architectures (REST, GraphQL, SOAP)',
                    'Knowledge of HTTP methods and status codes',
                    'Familiarity with authentication mechanisms',
                    'Understanding of data serialization formats'
                ],
                'setup': [
                    'Set up API testing environment',
                    'Install API testing tools',
                    'Configure authentication credentials',
                    'Prepare test data and payloads'
                ],
                'methodology': [
                    '1. API Discovery: Identify all API endpoints',
                    '2. Authentication Testing: Test authentication mechanisms',
                    '3. Authorization Testing: Test access controls and permissions',
                    '4. Data Validation: Test input validation and sanitization',
                    '5. Rate Limiting: Test API rate limiting and throttling',
                    '6. Error Handling: Test error responses and information disclosure',
                    '7. Business Logic: Test API business logic flaws',
                    '8. Configuration: Test API security configurations'
                ],
                'tools': {
                    'Postman': 'API development and testing platform',
                    'Burp Suite': 'Web application security testing with API support',
                    'OWASP ZAP': 'Security testing proxy with API scanning',
                    'Insomnia': 'API testing and development platform',
                    'Newman': 'Command-line collection runner for Postman'
                },
                'reporting': 'Document API-specific vulnerabilities with request/response examples and impact analysis'
            },
            'iot_security': {
                'title': 'IoT Security Testing Guide - How to Test',
                'overview': 'Comprehensive methodology for testing Internet of Things (IoT) device security.',
                'prerequisites': [
                    'Understanding of IoT architectures and protocols',
                    'Knowledge of embedded systems',
                    'Familiarity with wireless communication protocols',
                    'Basic hardware analysis skills'
                ],
                'setup': [
                    'Set up IoT testing laboratory',
                    'Prepare hardware analysis tools',
                    'Configure network monitoring equipment',
                    'Install firmware analysis tools'
                ],
                'methodology': [
                    '1. Processing Units: Test processors and microcontrollers',
                    '2. Memory Security: Analyze memory protection mechanisms',
                    '3. Firmware Security: Test firmware integrity and security',
                    '4. Data Exchange Services: Test data transmission security',
                    '5. Internal Interfaces: Test internal communication interfaces',
                    '6. Physical Interfaces: Test physical access points',
                    '7. Wireless Interfaces: Test wireless communication security',
                    '8. User Interfaces: Test user interaction security'
                ],
                'tools': {
                    'Hardware analysis tools': 'Oscilloscopes, logic analyzers, JTAG debuggers',
                    'Firmware analysis tools': 'Binwalk, Firmware Analysis Toolkit',
                    'Network scanners': 'Nmap, wireless protocol analyzers',
                    'Protocol analyzers': 'Wireshark, specialized IoT protocol tools'
                },
                'reporting': 'Document hardware and firmware security issues with technical details and remediation steps'
            },
            'asvs': {
                'title': 'Application Security Verification Standard - How to Test',
                'overview': 'Verification-based approach to application security testing using OWASP ASVS requirements.',
                'prerequisites': [
                    'Understanding of application security principles',
                    'Knowledge of secure development practices',
                    'Familiarity with security testing methodologies',
                    'Understanding of risk assessment'
                ],
                'setup': [
                    'Choose appropriate ASVS verification level (1, 2, or 3)',
                    'Set up comprehensive testing environment',
                    'Prepare security testing tools',
                    'Configure static and dynamic analysis tools'
                ],
                'methodology': [
                    '1. Level 1 Basic: Essential security controls verification',
                    '2. Level 2 Standard: Defense in depth verification',
                    '3. Level 3 Advanced: High-value application verification',
                    '4. Architecture Review: Verify security architecture',
                    '5. Authentication Testing: Verify authentication controls',
                    '6. Session Management: Verify session security',
                    '7. Access Control: Verify authorization mechanisms',
                    '8. Data Protection: Verify data security controls'
                ],
                'tools': {
                    'Static analysis tools': 'SonarQube, Checkmarx, Veracode',
                    'Dynamic analysis tools': 'Burp Suite, OWASP ZAP',
                    'Interactive testing tools': 'Manual testing combined with automation',
                    'Code review tools': 'Security-focused code review platforms'
                },
                'reporting': 'Document verification results against ASVS requirements with compliance status'
            },
            # 'cloud_security': {
            #     'title': 'Cloud Security Testing Guide - How to Test',
            #     'overview': 'Comprehensive methodology for testing cloud infrastructure, applications, and services security including CIS benchmarks.',
            #     'prerequisites': [
            #         'Understanding of cloud service models (IaaS, PaaS, SaaS)',
            #         'Knowledge of cloud provider security features',
            #         'Familiarity with cloud architecture patterns',
            #         'Understanding of compliance frameworks (CIS, SOC2, etc.)'
            #     ],
            #     'setup': [
            #         'Set up cloud security testing environment',
            #         'Configure cloud security assessment tools',
            #         'Establish secure access to cloud resources',
            #         'Prepare compliance checking tools'
            #     ],
            #     'methodology': [
            #         '1. Identity & Access Management: Test IAM configurations',
            #         '2. Data Protection: Test encryption and data security',
            #         '3. Network Security: Test network configurations and controls',
            #         '4. Infrastructure Security: Test compute and storage security',
            #         '5. Monitoring & Logging: Test security monitoring capabilities',
            #         '6. Application Security: Test cloud-native application security',
            #         '7. Compliance Testing: Verify against standards (CIS, SOC2)',
            #         '8. Configuration Assessment: Test security configurations'
            #     ],
            #     'tools': {
            #         'Cloud security scanners': 'Provider-specific security assessment tools',
            #         'IAM analyzers': 'Tools for analyzing identity and access policies',
            #         'Configuration tools': 'Tools for checking security configurations',
            #         'CIS benchmark tools': 'Automated CIS compliance checking tools',
            #         'Compliance scanners': 'Multi-standard compliance assessment tools'
            #     },
            #     'reporting': 'Document cloud security findings with provider-specific remediation guidance and compliance status',
            #     'cis_benchmarks': {
            #         'overview': 'CIS (Center for Internet Security) benchmarks provide security configuration guidelines',
            #         'major_categories': [
            #             'CIS Control 1: Inventory and Control of Hardware Assets',
            #             'CIS Control 2: Inventory and Control of Software Assets', 
            #             'CIS Control 3: Continuous Vulnerability Management',
            #             'CIS Control 4: Controlled Use of Administrative Privileges',
            #             'CIS Control 5: Secure Configuration for Hardware/Software',
            #             'CIS Control 6: Maintenance, Monitoring and Analysis of Audit Logs',
            #             'CIS Control 13: Data Protection',
            #             'CIS Control 14: Controlled Access Based on Need to Know',
            #             'CIS Control 16: Account Monitoring and Control'
            #         ],
            #         'cloud_specific': [
            #             'AWS CIS Benchmark: Security configurations for AWS services',
            #             'Azure CIS Benchmark: Security configurations for Microsoft Azure',
            #             'GCP CIS Benchmark: Security configurations for Google Cloud Platform',
            #             'Kubernetes CIS Benchmark: Security configurations for Kubernetes'
            #         ],
            #         'testing_approach': 'Use automated tools to assess compliance with CIS benchmarks and manually verify critical configurations'
            #     }
            # }
        }
        
        return guides.get(framework_key, {
            'title': 'General Security Testing Guide',
            'overview': 'Basic security testing methodology',
            'prerequisites': ['Basic security knowledge'],
            'setup': ['Set up testing environment'],
            'methodology': ['Plan', 'Test', 'Report'],
            'tools': {'Basic tools': 'Standard security testing tools'},
            'reporting': 'Document findings with recommendations'
        })
