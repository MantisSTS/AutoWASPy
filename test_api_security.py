#!/usr/bin/env python3
"""
Test script to show API Security parsing results
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import create_app

def test_api_security():
    """Test API Security parsing in detail"""
    app = create_app()
    
    with app.app_context():
        from app.services.api_security_service import APISecurityService
        
        print("=== OWASP API Security Top 10 - 2023 Edition ===\n")
        
        try:
            api_data = APISecurityService.fetch_api_security_data()
            print(f"Successfully fetched {len(api_data)} API Security items from OWASP GitHub\n")
            
            for i, item in enumerate(api_data, 1):
                print(f"{i}. {item['id']} - {item['title']}")
                print(f"   Category: {item['category']}")
                print(f"   Risk Level: {item['risk_level']}")
                print(f"   Description: {item['description'][:150]}...")
                print()
                
        except Exception as e:
            print(f"Failed: {e}")
            import traceback
            traceback.print_exc()

if __name__ == '__main__':
    test_api_security()
