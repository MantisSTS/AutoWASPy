#!/usr/bin/env python3
"""
Test script for improved IoT Security Service with ISTG parsing
"""

import sys
import os
sys.path.append('/home/mantis/Tools/AutoWASPy')

# Set up Flask app context
from app import create_app
app = create_app()

with app.app_context():
    from app.services.iot_security_service import IoTSecurityService
    import json
    
    print("Testing improved IoT Security Service (ISTG)...")
    print("=" * 60)
    
    # Test the fetch function
    try:
        iot_data = IoTSecurityService.fetch_iot_security_data()
        
        print(f"Successfully fetched {len(iot_data)} IoT Security tests")
        print("\nTest Categories Found:")
        
        categories = {}
        for test in iot_data:
            category = test.get('category', 'Unknown')
            if category not in categories:
                categories[category] = []
            categories[category].append(test)
        
        for category, tests in categories.items():
            print(f"- {category}: {len(tests)} tests")
        
        print(f"\nFirst 10 tests:")
        print("-" * 40)
        
        for i, test in enumerate(iot_data[:10]):
            print(f"{i+1}. {test['id']} - {test['title']}")
            print(f"   Category: {test['category']}")
            print(f"   Risk: {test['risk_level']}")
            print(f"   Description: {test['description'][:100]}...")
            print()
        
        # Test specific ISTG categories
        print("\nTesting specific ISTG categories:")
        print("-" * 40)
        
        istg_categories = ['Processing Units', 'Memory Security', 'Firmware Security', 
                          'Data Exchange Services', 'Wireless Interfaces']
        
        for cat in istg_categories:
            cat_tests = [t for t in iot_data if cat in t['category']]
            if cat_tests:
                print(f"{cat}: {len(cat_tests)} tests")
                for test in cat_tests[:2]:  # Show first 2 tests in category
                    print(f"  - {test['id']}: {test['title']}")
            else:
                print(f"{cat}: No tests found")
        
        # Test risk level distribution
        print(f"\nRisk Level Distribution:")
        print("-" * 25)
        risk_levels = {}
        for test in iot_data:
            risk = test.get('risk_level', 'unknown')
            risk_levels[risk] = risk_levels.get(risk, 0) + 1
        
        for risk, count in risk_levels.items():
            print(f"- {risk.title()}: {count} tests")
        
        print(f"\nTotal tests fetched: {len(iot_data)}")
        
        # Save sample data to file for inspection
        sample_data = iot_data[:5]
        with open('/home/mantis/Tools/AutoWASPy/iot_sample_data.json', 'w') as f:
            json.dump(sample_data, f, indent=2)
        print("Sample data saved to iot_sample_data.json")
        
    except Exception as e:
        print(f"Error testing IoT Security Service: {e}")
        import traceback
        traceback.print_exc()
