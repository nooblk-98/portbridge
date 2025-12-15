
from flask import Blueprint, render_template
from flask_login import login_required

bp = Blueprint('main', __name__)

@bp.get("/")
@login_required
def index():
    return render_template("index.html")
