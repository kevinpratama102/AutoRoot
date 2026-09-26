from flask import *
from . import login_manager
from .models import db, User
from flask_autoindex import AutoIndex

import json

# Blueprint configuration.
main_bp = Blueprint('main_bp',
                    __name__,
                    template_folder='templates',
                    static_folder='static')

# assets config - locally uploaded.
assets_files_index = AutoIndex(
    main_bp, 'flask_internals/', add_url_rules=False)


@main_bp.route('/<path:path>')
def autoindex(path='.'):
    """
    Serving /css, images/, and /js paths 
    """
    return assets_files_index.render_autoindex('static/assets/' + path)


@main_bp.route('/')
@main_bp.route('/index.html')
def load_index():
    return render_template('index.html')


@main_bp.route('/products.html')
def load_products():
    return render_template('products.html')


@main_bp.route('/about.html')
def load_about():
    return render_template('about.html')


# ------------------ FIRST HINT ---------------------
@main_bp.route('/contact')
@main_bp.route('/contact.html')
def contact_json_response():
    """ 
    Return a json response in purpose, this is the 
    first hint for whoever solves this CTF - to think about json in later stages. 
    """
    server_info = {
        "server_info": {
            "status": "removed from production",
            "reason": "bugs fixes & better frontend desgin"
        }
    }
    return json.dumps(server_info)


# ------------------ RABBIT HOLE + Hint ---------------------
@main_bp.route('/configure')
def load_configure():
    """
    Return a json response again.
    Contains rabbit hole (db version) + hint (wordlist)
    """
    db_config = {
        "db_config": {
            "VERSION": "MariaDB 5.5.52"
        },
        "dict_path": {
            "source": "aHR0cHM6Ly9wYXN0ZWJpbi5jb20vWmN4UzJkaUI="
        }
    }
    return json.dumps(db_config)


# ------------------ SECOND HINT  - contains admin-dir/ ---------------------
@main_bp.route('/robots.txt')
def load_robots_txt():
    return main_bp.send_static_file('robots.txt')


# in order to get this dir, reverse the common wordlists you are using, think outside the box.
# learn an important lesson - there is no "wordlist winner".
@main_bp.route('/admin-dir/hideshar')
def load_admin_dir(path='.'):
    """Include the uploads directory.
    Contains: PDF file with hint, python code."""
    return assets_files_index.render_autoindex('admin-dir/admin_uploads/' + path)


@main_bp.route('/admin-dir/admin_uploads/<path:filename>', methods=['GET', 'POST'])
def download_handler(filename):
    """
    Serve admin_uploads directory.
    Directory contains some hints in order to get to the admin panel.
    """
    return send_from_directory(directory='admin-dir/admin_uploads', filename=filename)


@login_manager.user_loader
def load_user(user_id):
    """
    Check if user is logged-in upon page load.
    """
    if user_id is not None:
        return User.query.get(user_id)
    return None


@login_manager.unauthorized_handler
def unauthorized():
    """
    Redirect unauthorized users to Login page.
    """
    flash('You must be logged in to view that page.')
    return redirect(url_for('auth_bp.admin_login'))
