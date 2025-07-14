#!/usr/bin/env python3
"""
Script to update existing test items with enhanced descriptions
"""

from app import app, db, TestItem, OWASPService

def update_test_descriptions():
    """Update existing test items with enhanced fallback descriptions"""
    
    with app.app_context():
        # Get enhanced descriptions
        wstg_data = OWASPService._get_fallback_wstg_data()
        mstg_data = OWASPService._get_fallback_mstg_data()
        
        # Create lookup dictionaries
        wstg_lookup = {item['id']: item['description'] for item in wstg_data}
        mstg_lookup = {item['id']: item['description'] for item in mstg_data}
        
        # Update WSTG items
        updated_count = 0
        wstg_items = TestItem.query.filter_by(test_type='wstg').all()
        
        for item in wstg_items:
            if item.owasp_id in wstg_lookup:
                old_desc = item.description
                item.description = wstg_lookup[item.owasp_id]
                updated_count += 1
                print(f"Updated {item.owasp_id}: {old_desc[:50]}... -> {item.description[:50]}...")
        
        # Update MSTG items
        mstg_items = TestItem.query.filter_by(test_type='mstg').all()
        
        for item in mstg_items:
            if item.owasp_id in mstg_lookup:
                old_desc = item.description
                item.description = mstg_lookup[item.owasp_id]
                updated_count += 1
                print(f"Updated {item.owasp_id}: {old_desc[:50]}... -> {item.description[:50]}...")
        
        # Commit changes
        try:
            db.session.commit()
            print(f"\nSuccessfully updated {updated_count} test items with enhanced descriptions!")
        except Exception as e:
            db.session.rollback()
            print(f"Error updating descriptions: {e}")

if __name__ == '__main__':
    update_test_descriptions()
