"""
Comprehensive OWASP Security Testing Framework Integration Service
Provides unified access to all OWASP testing guides and frameworks
"""

from app.services.owasp_service import OWASPService
from app.services.api_security_service import APISecurityService
from app.services.iot_security_service import IoTSecurityService
from app.services.asvs_service import ASVSService
from app.services.cloud_security_service import CloudSecurityService

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
            'cloud_security': {
                'name': 'Cloud Security Testing Guide',
                'description': 'Cloud security testing based on industry best practices',
                'version': '1.0',
                'categories': ['Identity and Access Management', 'Data Protection', 'Network Security', 'Infrastructure Security', 'Monitoring and Logging', 'Application Security', 'Compliance and Governance', 'Disaster Recovery']
            }
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
            elif framework_name == 'cloud_security':
                return CloudSecurityService.fetch_cloud_security_data()
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
            'cloud': ['cloud_security', 'asvs', 'api_security', 'wstg'],
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
            'high': ['wstg', 'mstg', 'api_security', 'asvs', 'iot_security', 'cloud_security']
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
                    'asvs': 0.5,
                    'cloud_security': 0.75
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
                    'asvs': 'asvs',
                    'cloud_security': 'cloud_security'
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
            'cloud_security': {
                'approach': 'Cloud infrastructure and application security testing',
                'tools': ['Cloud security scanners', 'IAM analyzers', 'Configuration assessment tools'],
                'phases': ['Identity & Access Testing', 'Data Protection Testing', 'Network Security Testing', 'Configuration Assessment', 'Monitoring Validation']
            }
        }
        
        return methodologies.get(framework_key, {
            'approach': 'General security testing methodology',
            'tools': ['Security testing tools'],
            'phases': ['Planning', 'Testing', 'Reporting']
        })
