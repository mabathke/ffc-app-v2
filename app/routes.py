# app/routes.py

from functools import wraps
from flask import Blueprint, render_template, url_for, flash, redirect, request, abort
from app.forms import RegistrationForm, LoginForm, AddFishForm, DeleteFishForm, FangmeldungForm, EditFishForm, GenerateInviteForm
from app.models import User, Fish, Catch, Invitation
from app import db, bcrypt, limiter
from flask_login import login_user, current_user, logout_user, login_required
from sqlalchemy import func
from datetime import datetime

main = Blueprint('main', __name__)

@main.route("/")
@main.route("/home")
def home():
    catches =  Catch.query.order_by(Catch.timestamp.desc()).all()
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
@limiter.limit("10 per hour") # to prevent brute force attacks
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        # Retrieve the invitation
        invitation = Invitation.query.filter_by(code=form.invite_code.data, is_used=False).first()
        if invitation and invitation.email == form.email.data:
            # Optionally, check for expiration
            if invitation.expires_at < datetime.utcnow():
                flash('Der Einladungscode ist abgelaufen.', 'danger')
                return redirect(url_for('main.register'))
            # Hash the password
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            # Create a new user
            user = User(username=form.username.data, email=form.email.data, password=hashed_password)
            db.session.add(user)
            # Mark the invitation as used
            invitation.is_used = True
            db.session.commit()
            flash('Dein Konto wurde erstellt! Du kannst dich jetzt einloggen.', 'success')
            return redirect(url_for('main.login'))
        else:
            flash('Ungültiger Einladungscode oder E-Mail-Adresse.', 'danger')
    return render_template('register.html', title='Registrieren', form=form)

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
            flash('Du wurdest erfolgreich eingeloggt!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('main.home'))
        else:
            flash('Login fehlgeschlagen. Bitte überprüfe E-Mail und Passwort.', 'danger')
    return render_template('login.html', title='Login', form=form)

@main.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('main.home'))

@main.route("/account")
@login_required
def account():
    return render_template('account.html', title='Konto')

# Decorator to restrict routes to admin users
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Du hast keine Berechtigung, auf diese Seite zuzugreifen.', 'danger')
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
            multiplicator=form.multiplicator.data,
            above_average=form.above_average.data,
            monster=form.monster.data,
        )
        db.session.add(fish)
        db.session.commit()
        flash(f'Fisch "{form.name.data}" wurde hinzugefügt.', 'success')
        return redirect(url_for('main.manage_fish'))
    return render_template('add_fish.html', title='Fisch hinzufügen', form=form)


@main.route("/admin/delete_fish", methods=['GET', 'POST'])
@login_required
@admin_required
def delete_fish():
    form = DeleteFishForm()
    if form.validate_on_submit():
        fish = Fish.query.filter_by(name=form.name.data).first()
        if not fish:
            flash('Der angegebene Fisch existiert nicht.', 'danger')
            return redirect(url_for('main.manage_fish'))
        
        # Überprüfen, ob der Fisch zugehörige Fänge hat
        if fish.catches:
            flash('Dieser Fisch kann nicht gelöscht werden, da er zugehörige Fänge hat.', 'danger')
            return redirect(url_for('main.manage_fish'))
        
        db.session.delete(fish)
        db.session.commit()
        flash(f'Fisch "{form.name.data}" wurde gelöscht.', 'success')
        return redirect(url_for('main.manage_fish'))
    return render_template('delete_fish.html', title='Fisch löschen', form=form)

@main.route("/admin/manage_fish")
@login_required
@admin_required
def manage_fish():
    fishes = Fish.query.all()
    return render_template('manage_fish.html', title='Fische verwalten', fishes=fishes)

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
    
    catches_per_user = []
    
    if current_user.is_authenticated:
        catches_per_user = Catch.query.filter_by(user_id=current_user.id)\
                               .order_by(Catch.timestamp.desc())\
                               .all()
    
    if not fishes:
        flash('Keine Fische verfügbar. Bitte kontaktiere den Administrator.', 'warning')
        return redirect(url_for('main.home'))
    
    if form.validate_on_submit():
        selected_fish = Fish.query.get(form.fish.data)
        if not selected_fish:
            flash('Der ausgewählte Fisch existiert nicht.', 'danger')
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
        flash(f'Dein Fang von {int(length)} cm für "{selected_fish.name}" wurde erfasst. Vergabene Punkte: {int(points)}.', 'success')
        return redirect(url_for('main.fangmeldung'))
    
    return render_template('fangmeldung.html', title='Fangmeldung', form=form, catches_per_user=catches_per_user)

@main.route("/admin/edit_fish/<int:fish_id>", methods=['GET', 'POST'])
@login_required
@admin_required
def edit_fish(fish_id):
    fish = Fish.query.get_or_404(fish_id)
    form = EditFishForm()

    if form.validate_on_submit():
        fish.multiplicator = form.multiplicator.data
        fish.above_average = form.above_average.data
        fish.monster = form.monster.data
        db.session.commit()
        flash(f'Die Werte von "{fish.name}" wurden erfolgreich aktualisiert.', 'success')
        return redirect(url_for('main.manage_fish'))
    
    elif request.method == 'GET':
        form.multiplicator.data = fish.multiplicator
        form.above_average.data = fish.above_average
        form.monster.data = fish.monster

    return render_template('edit_fish.html', title='Fisch bearbeiten', form=form, fish=fish)


@main.route("/manage_invitations", methods=['GET', 'POST'])
@login_required
@admin_required
def manage_invitations():
    form = GenerateInviteForm()
    if form.validate_on_submit():
        # Generate unique 6-digit code
        code = Invitation.generate_unique_code()
        # Create a new invitation
        invitation = Invitation(email=form.email.data, code=code)
        db.session.add(invitation)
        db.session.commit()
        # Flash the code to the admin
        flash(f'Einladungscode für {form.email.data}: {code}', 'success')
        return redirect(url_for('main.manage_invitations'))
    
    # Fetch all invitations (optional: exclude sensitive data)
    invitations = Invitation.query.order_by(Invitation.created_at.desc()).all()
    return render_template('manage_invitations.html', title='Einladungen verwalten', form=form, invitations=invitations)

@main.route('/delete_catch/<int:catch_id>', methods=['POST'])
@login_required
def delete_catch(catch_id):
    catch = Catch.query.get_or_404(catch_id)
    
    # Ensure the catch belongs to the current user
    if catch.user_id != current_user.id:
        abort(403)  # Forbidden
    
    db.session.delete(catch)
    db.session.commit()
    flash('Dein Fang wurde erfolgreich gelöscht.', 'success')
    return redirect(url_for('main.fangmeldung'))