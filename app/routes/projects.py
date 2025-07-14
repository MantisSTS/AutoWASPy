"""
Project management routes
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash
from app import db
from app.models import Project, TestItem
from app.services import OWASPService, APISecurityService, IoTSecurityService, ASVSService
# from app.services.cloud_security_service import CloudSecurityService
from app.utils import utc_now

bp = Blueprint('projects', __name__, url_prefix='/project')

@bp.route('/new', methods=['GET', 'POST'])
def new_project():
    """Create a new project"""
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
        # Using cached/fallback data for fast project creation
        # Use Admin > Refresh OWASP Data to update from GitHub
        if project.job_type == 'web':
            tests = OWASPService.get_cached_wstg_data()
            test_type = 'wstg'
        elif project.job_type in ['mobile_ios', 'mobile_android']:
            tests = OWASPService.get_cached_mstg_data()
            test_type = 'mstg'
        elif project.job_type == 'api_security':
            tests = APISecurityService.get_cached_api_security_data()
            test_type = 'api_security'
        elif project.job_type == 'iot_security':
            tests = IoTSecurityService.get_cached_iot_security_data()
            test_type = 'iot_security'
        elif project.job_type == 'asvs_verification':
            tests = ASVSService.get_cached_asvs_data()
            test_type = 'asvs'
        # elif project.job_type == 'cloud_security':
        #     tests = CloudSecurityService.get_cached_cloud_security_data()
        #     test_type = 'cloud_security'
        else:
            tests = []
            test_type = 'unknown'
        
        for test_data in tests:
            test_item = TestItem(
                project_id=project.id,
                owasp_id=test_data['id'],
                title=test_data['title'],
                description=test_data['description'],
                full_description=test_data.get('full_description', test_data['description']),
                category=test_data['category'],
                test_type=test_type
            )
            db.session.add(test_item)
        
        db.session.commit()
        flash(f'Project "{project.name}" created successfully!', 'success')
        return redirect(url_for('projects.project_detail', project_id=project.id))
    
    return render_template('new_project.html')

@bp.route('/<int:project_id>')
def project_detail(project_id):
    """Show project details and test items"""
    project = db.get_or_404(Project, project_id)
    test_items = TestItem.query.filter_by(project_id=project_id).order_by(TestItem.category, TestItem.owasp_id).all()
    
    # Group test items by category
    categories = {}
    for item in test_items:
        if item.category not in categories:
            categories[item.category] = []
        categories[item.category].append(item)
    
    return render_template('project_detail.html', project=project, categories=categories)

@bp.route('/<int:project_id>/test/<int:test_id>/update', methods=['POST'])
def update_test_item(project_id, test_id):
    """Update a test item with evidence and status"""
    test_item = db.get_or_404(TestItem, test_id)
    
    test_item.is_tested = request.form.get('is_tested') == 'on'
    test_item.evidence = request.form.get('evidence', '')
    test_item.finding_status = request.form.get('finding_status', 'not_tested')
    test_item.risk_level = request.form.get('risk_level', '')
    test_item.updated_date = utc_now()
    
    db.session.commit()
    flash('Test item updated successfully!', 'success')
    return redirect(url_for('projects.project_detail', project_id=project_id))

@bp.route('/<int:project_id>/delete', methods=['POST'])
def delete_project(project_id):
    """Delete a project and all associated test items"""
    project = db.get_or_404(Project, project_id)
    
    try:
        # Delete associated test items (handled by cascade)
        # Delete auto test results
        from app.models import AutoTestResult
        AutoTestResult.query.filter_by(project_id=project_id).delete()
        
        # Delete the project
        db.session.delete(project)
        db.session.commit()
        
        flash(f'Project "{project.name}" has been deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting project: {str(e)}', 'error')
    
    return redirect(url_for('main.index'))
