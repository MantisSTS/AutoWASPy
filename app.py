"""
Simplified modular Flask application
"""
import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
import html
from markupsafe import Markup
from dotenv import load_dotenv
import urllib3
import requests
import re
import json
import io
import csv
import time
from typing import List, Dict

# Load environment variables
load_dotenv()

# Suppress SSL warnings for testing environments
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-change-this')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///instance/autowaspy.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# Helper function for timezone-aware UTC datetime
def utc_now():
    """Return current UTC time in timezone-aware format"""
    return datetime.now(timezone.utc)

# Initialize models with db instance
import app.models
app.models.db = db
app.models.init_models(db)

# Import models after initialization
from app.models import Project, TestItem, AutoTestResult, OWASPDataCache

# Import services
from app.services import OWASPService, AutoTestService

# Custom Jinja2 filters
@app.template_filter('safe_format_description')
def safe_format_description(description):
    """Safely format test descriptions while preventing XSS"""
    if not description:
        return ""
    
    # Escape all HTML to prevent XSS
    escaped = html.escape(description)
    
    # Replace line breaks with HTML breaks (safe since we escaped everything)
    formatted = escaped.replace('\n', '<br>')
    
    # Return as Markup object so it's treated as safe HTML
    return Markup(formatted)

@app.template_filter('safe_escape')
def safe_escape(content):
    """Safely escape content to prevent XSS"""
    if not content:
        return ""
    return html.escape(str(content))

# Simple routes (we'll add blueprints later)
@app.route('/')
def index():
    projects = Project.query.order_by(Project.created_date.desc()).all()
    return render_template('index.html', projects=projects)

@app.route('/project/new', methods=['GET', 'POST'])
def new_project():
    if request.method == 'POST':
        project = Project(
            name=request.form['name'],
            client_name=request.form['client_name'],
            job_type=request.form['job_type'],
            description=request.form.get('description', ''),
            urls=request.form.get('urls', '')
        )
        
        db.session.add(project)
        db.session.commit()
        
        # Initialize test items based on job type
        if project.job_type == 'web':
            tests = OWASPService.fetch_wstg_data()
            test_type = 'wstg'
        else:  # mobile
            tests = OWASPService.fetch_mstg_data()
            test_type = 'mstg'
        
        for test_data in tests:
            test_item = TestItem(
                project_id=project.id,
                owasp_id=test_data['id'],
                title=test_data['title'],
                description=test_data['description'],
                category=test_data['category'],
                test_type=test_type
            )
            db.session.add(test_item)
        
        db.session.commit()
        flash(f'Project "{project.name}" created successfully!', 'success')
        return redirect(url_for('project_detail', project_id=project.id))
    
    return render_template('new_project.html')

@app.route('/project/<int:project_id>')
def project_detail(project_id):
    project = db.get_or_404(Project, project_id)
    test_items = TestItem.query.filter_by(project_id=project_id).order_by(TestItem.category, TestItem.owasp_id).all()
    
    # Group test items by category
    categories = {}
    for item in test_items:
        if item.category not in categories:
            categories[item.category] = []
        categories[item.category].append(item)
    
    return render_template('project_detail.html', project=project, categories=categories)

# Create database tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5001))
    app.run(debug=True, host='0.0.0.0', port=port)
