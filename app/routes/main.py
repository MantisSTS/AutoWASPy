"""
Main application routes
"""
from flask import Blueprint, render_template
from app.models import Project

bp = Blueprint('main', __name__)

@bp.route('/')
def index():
    """Home page showing all projects"""
    projects = Project.query.order_by(Project.created_date.desc()).all()
    return render_template('index.html', projects=projects)
