"""
Database models for AutoWASPy application
"""
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy

def utc_now():
    """Return current UTC time in timezone-aware format"""
    return datetime.now(timezone.utc)

# db will be injected by the app factory
db = None

def init_models(database):
    """Initialize models with the database instance"""
    global db
    db = database

def create_models(database):
    """Create all model classes and return them"""
    
    class Project(database.Model):
        """Project model for storing penetration testing project information"""
        id = database.Column(database.Integer, primary_key=True)
        name = database.Column(database.String(100), nullable=False)
        client_name = database.Column(database.String(100), nullable=False)
        job_type = database.Column(database.String(20), nullable=False)  # 'web', 'mobile_ios', 'mobile_android', 'api_security', 'iot_security', 'asvs_verification'
        created_date = database.Column(database.DateTime, default=utc_now)
        description = database.Column(database.Text)
        urls = database.Column(database.Text)  # JSON string of URLs for web tests
        status = database.Column(database.String(20), default='active')  # 'active', 'completed', 'archived'
        
        # Relationships
        test_items = database.relationship('TestItem', backref='project', lazy=True, cascade='all, delete-orphan')
        auto_test_results = database.relationship('AutoTestResult', backref='project', lazy=True, cascade='all, delete-orphan')

    class TestItem(database.Model):
        """Test item model for individual OWASP test cases"""
        id = database.Column(database.Integer, primary_key=True)
        project_id = database.Column(database.Integer, database.ForeignKey('project.id'), nullable=False)
        owasp_id = database.Column(database.String(20), nullable=False)
        title = database.Column(database.String(200), nullable=False)
        description = database.Column(database.Text)
        category = database.Column(database.String(100))
        test_type = database.Column(database.String(20), nullable=False)  # 'wstg', 'mstg', 'api_security', 'iot_security', 'asvs'
        is_tested = database.Column(database.Boolean, default=False)
        evidence = database.Column(database.Text)
        risk_level = database.Column(database.String(20))  # 'low', 'medium', 'high', 'critical'
        finding_status = database.Column(database.String(20), default='not_tested')  # 'not_tested', 'pass', 'fail', 'informational'
        created_date = database.Column(database.DateTime, default=utc_now)
        updated_date = database.Column(database.DateTime, default=utc_now, onupdate=utc_now)

    class AutoTestResult(database.Model):
        """Model for storing automated test results"""
        id = database.Column(database.Integer, primary_key=True)
        project_id = database.Column(database.Integer, database.ForeignKey('project.id'), nullable=False)
        test_name = database.Column(database.String(100), nullable=False)
        url_tested = database.Column(database.String(500))
        result = database.Column(database.String(20))  # 'pass', 'fail', 'error'
        evidence = database.Column(database.Text)
        request_data = database.Column(database.Text)
        response_data = database.Column(database.Text)
        created_date = database.Column(database.DateTime, default=utc_now)

    class OWASPDataCache(database.Model):
        """Cache table for OWASP data updates"""
        id = database.Column(database.Integer, primary_key=True)
        data_type = database.Column(database.String(20), nullable=False)  # 'wstg', 'mstg', 'api_security', 'iot_security', 'asvs'
        last_updated = database.Column(database.DateTime, default=utc_now)
        data_source = database.Column(database.String(50), default='github')  # 'github' or 'fallback'
        test_count = database.Column(database.Integer, default=0)
    
    return Project, TestItem, AutoTestResult, OWASPDataCache

# We'll create these dynamically when init_models is called
Project = None
TestItem = None  
AutoTestResult = None
OWASPDataCache = None

def init_models(database):
    """Initialize models with the database instance"""
    global db, Project, TestItem, AutoTestResult, OWASPDataCache
    db = database
    Project, TestItem, AutoTestResult, OWASPDataCache = create_models(database)

# Export all models for easy importing
__all__ = ['Project', 'TestItem', 'AutoTestResult', 'OWASPDataCache', 'db', 'utc_now', 'init_models']
