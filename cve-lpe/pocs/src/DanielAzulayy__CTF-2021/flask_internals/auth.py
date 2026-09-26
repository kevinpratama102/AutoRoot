from flask import *
from .forms import LoginForm, SignupForm
from flask_login import login_user, login_required, logout_user
from .models import User

import os.path
import json


auth_bp = Blueprint('auth_bp',
                    __name__,
                    template_folder='templates',
                    static_folder='static')


@auth_bp.route('/admin-dir/hideshar/pollogin', methods=['GET', 'POST'])
def admin_login():
    """Log-in page for registered users.
    GET requests serve Log-in page.
    POST requests validate and redirect user to dashboard."""
    form = LoginForm()
    if form.validate_on_submit():
        # check for a specifc email & password - just for CTF purposes.
        # avoid any interatcion with the db - SQLi isn't the goal here.
        if form.email.data == "avi@6clothing.co.il" and form.password.data == "any6gkbi":
            user = User.query.filter_by(email=form.email.data).first()
            if user:
                login_user(user)
                response = make_response(
                    redirect('/admin-dir/hideshar/dashboard/index.html'))
                response.set_cookie(
                    'security_token', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImF2aSIsImlzX2FkbWluIjoiZmFsc2UifQ.cPwoXIJmCricMpXSMsuxKw6w2dikZMPQSDEfza0lgUw')
                return response

        flash('Invalid email/password')
        return redirect(url_for('auth_bp.admin_login'))

    return render_template(
        'admin_login/login.jinja2',
        form=form,
        title='Log in',
        template='login-page',
        body="Log in with your User."
    )


@ auth_bp.route('/admin-dir/hideshar/signup', methods=['GET', 'POST'])
def signup():
    """
    User sign-up page. Just a trap, it's never really signing up.
    GET requests serve sign-up page.
    POST requests validate form & user creation.
    """
    form = SignupForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            # this gives an indication - this email is in use.
            flash('A user already exists with that email address.')
            return redirect(url_for('auth_bp.signup'))

        return redirect(url_for('auth_bp.admin_login'))

    return render_template(
        'admin_login/signup.jinja2',
        title='Create an Account',
        form=form,
        template='signup-page',
        body="Sign up for a user."
    )


@auth_bp.route('/admin-dir/hideshar/dashboard/index.html', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard/index.html')


@auth_bp.route('/admin-dir/hideshar/dashboard/ui-maps.html')
def load_maps():
    return render_template('dashboard/ui-maps.html')


@auth_bp.route('/admin-dir/hideshar/dashboard/ui-icons.html')
@login_required
def load_icons():
    return render_template('dashboard/ui-icons.html')


@auth_bp.route('/admin-dir/hideshar/dashboard/ui-notifications.html')
@login_required
def load_nof():
    return render_template('dashboard/ui-notifications.html')


@auth_bp.route('/admin-dir/hideshar/dashboard/page-user.html')
@login_required
def load_page_user_html():
    return render_template('dashboard/page-user.html')


@auth_bp.route('/admin-dir/hideshar/dashboard/register', methods=['GET', 'POST'])
def register():
    # is_admin = "true" jwt token.
    admin_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImF2aSIsImlzX2FkbWluIjoidHJ1ZSJ9.u8LzXJfYJ5QC38nd994YvdfUyMZIHm87MtnDcySUIx0'
    user_token = request.args.get('token')

    if admin_token == user_token:
        return redirect(url_for('auth_bp.registered'))

    else:
        return Response(
            'Could not verify your access level for that URL.\n'
            'You have to login with proper credentials', 401)


@auth_bp.route('/admin-dir/hideshar/dashboard/registered_users', methods=['GET', 'POST'])
@login_required
def registered():
    content = request.args.get('id', None)
    if content:
        return render_template_string(content)

    return json.dumps({'register_path': 'registered_users?id='})


@auth_bp.route("/admin-dir/hideshar/dashboard/")
@login_required
def logout():
    """
    User log-out.
    """
    logout_user()
    return redirect(url_for('auth_bp.admin_login'))
