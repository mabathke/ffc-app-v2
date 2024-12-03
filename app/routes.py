# app/routes.py

from functools import wraps
from flask import Blueprint, render_template, url_for, flash, redirect, request
from app.forms import RegistrationForm, LoginForm, AddFishForm, DeleteFishForm, FangmeldungForm
from app.models import User, Fish, Catch
from app import db, bcrypt
from flask_login import login_user, current_user, logout_user, login_required
from sqlalchemy import func

main = Blueprint('main', __name__)

@main.route("/")
@main.route("/home")
def home():
    catches = Catch.query.all()
    catches_per_user = []
    
    # Aggregate total points per user
    rankings = db.session.query(
        User.username,
        func.sum(Catch.points).label('total_points')
    ).join(Catch).group_by(User.id).order_by(func.sum(Catch.points).desc()).all()
    
    if current_user.is_authenticated:
        catches_per_user = Catch.query.filter_by(user_id=current_user.id).all()
    
    return render_template('dashboard.html', title='Home', catches=catches, catches_per_user=catches_per_user, rankings=rankings)

@main.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html', title='Register', form=form)

@main.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash('You have been logged in!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('main.home'))
        else:
            flash('Login Unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html', title='Login', form=form)

@main.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('main.home'))

@main.route("/account")
@login_required
def account():
    return render_template('account.html', title='Account')

# Decorator to restrict routes to admin users
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('main.home'))
        return f(*args, **kwargs)
    return decorated_function

@main.route("/admin/add_fish", methods=['GET', 'POST'])
@login_required
@admin_required
def add_fish():
    form = AddFishForm()
    if form.validate_on_submit():
        
        fish = Fish(
            name=form.name.data,
            lower_bound = form.lower_bound.data,
            avg_length= form.avg_length.data,
            upper_bound = form.upper_bound.data,
            is_rare = form.is_rare.data,
        )
        db.session.add(fish)
        db.session.commit()
        flash(f'Fish "{form.name.data}" has been added.', 'success')
        return redirect(url_for('main.manage_fish'))
    return render_template('add_fish.html', title='Add Fish', form=form)

@main.route("/admin/delete_fish", methods=['GET', 'POST'])
@login_required
@admin_required
def delete_fish():
    form = DeleteFishForm()
    if form.validate_on_submit():
        fish = Fish.query.filter_by(name=form.name.data).first()
        db.session.delete(fish)
        db.session.commit()
        flash(f'Fish "{form.name.data}" has been deleted.', 'success')
        return redirect(url_for('main.manage_fish'))
    return render_template('delete_fish.html', title='Delete Fish', form=form)

@main.route("/admin/manage_fish")
@login_required
@admin_required
def manage_fish():
    fishes = Fish.query.all()
    return render_template('manage_fish.html', title='Manage Fish', fishes=fishes)

@main.route("/rules")
@login_required
def rules():
    fishes = Fish.query.all()
    return render_template('rules.html', title='Regeln', fishes=fishes)


@main.route('/fangmeldung', methods=['GET', 'POST'])
@login_required
def fangmeldung():
    form = FangmeldungForm()
    
    # Populate the fish choices
    fishes = Fish.query.order_by(Fish.name).all()
    form.fish.choices = [(fish.id, fish.name) for fish in fishes]
    
    if not fishes:
        flash('No fish available. Please contact the administrator.', 'warning')
        return redirect(url_for('main.home'))
    
    if form.validate_on_submit():
        selected_fish = Fish.query.get(form.fish.data)
        if not selected_fish:
            flash('Selected fish does not exist.', 'danger')
            return redirect(url_for('main.fangmeldung'))
        
        length = form.length.data
        lower_bound = selected_fish.lower_bound
        upper_bound = selected_fish.upper_bound
        avg_length = selected_fish.avg_length  # Use static avg_length from Fish table
        is_rare = selected_fish.is_rare
        
        # Calculate points based on the rules
        if length < lower_bound:
            points = 0
        elif lower_bound <= length < avg_length:
            points = length * 0.5
        elif avg_length <= length <= upper_bound:
            points = length * 1
        elif length > upper_bound:
            points = length * 1.5
        
        # Apply rare fish multiplier
        if is_rare:
            points *= 2
        
        # Log the catch with calculated points
        new_catch = Catch(
            length=length,
            fish_id=selected_fish.id,
            user_id=current_user.id,
            points=points
        )
        db.session.add(new_catch)
        
        db.session.commit()
        flash(f'Your catch of {length} cm for "{selected_fish.name}" has been recorded. Points awarded: {points}', 'success')
        return redirect(url_for('main.home'))
    
    return render_template('fangmeldung.html', title='Fangmeldung', form=form)