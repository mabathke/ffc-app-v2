# app/routes.py

from functools import wraps
from flask import Blueprint, render_template, url_for, flash, redirect, request, abort
from app.forms import (RegistrationForm, LoginForm, AddFishForm, DeleteFishForm, 
                       FangmeldungForm, EditFishForm, GenerateInviteForm, CreateChallengeForm)
from app.models import ChallengeParticipation, User, Fish, Catch, Invitation, Challenge, Catch
from app import db, bcrypt, limiter
from flask_login import login_user, current_user, logout_user, login_required
from sqlalchemy import func
from datetime import datetime, timedelta

main = Blueprint('main', __name__)

@main.route("/")
@main.route("/home")
def home():
    now = datetime.utcnow()

    # Retrieve all catches (ordered by timestamp descending)
    catches = Catch.query.order_by(Catch.timestamp.desc()).all()
    if current_user.is_authenticated:
        catches_per_user = Catch.query.filter_by(user_id=current_user.id).all()
    else:
        catches_per_user = []

    # Subquery for catch points per user
    catch_subq = db.session.query(
        Catch.user_id,
        func.coalesce(func.sum(Catch.points), 0).label('catch_points')
    ).group_by(Catch.user_id).subquery()

    # Subquery for challenge points (only from expired challenges, both winners and losers)
    challenge_subq = db.session.query(
        ChallengeParticipation.user_id,
        func.coalesce(func.sum(ChallengeParticipation.awarded_points), 0).label('challenge_points')
    ).join(Challenge, Challenge.id == ChallengeParticipation.challenge_id)\
     .filter(Challenge.expiration_time <= now)\
     .group_by(ChallengeParticipation.user_id).subquery()

    # Join the subqueries with User to compute total points per user
    rankings = db.session.query(
        User.username,
        (func.coalesce(catch_subq.c.catch_points, 0) + func.coalesce(challenge_subq.c.challenge_points, 0)).label('total_points')
    ).outerjoin(catch_subq, catch_subq.c.user_id == User.id)\
     .outerjoin(challenge_subq, challenge_subq.c.user_id == User.id)\
     .order_by((func.coalesce(catch_subq.c.catch_points, 0) + func.coalesce(challenge_subq.c.challenge_points, 0)).desc())\
     .all()

    # Query *all* finished challenges (whether or not there's a winner)
    finished_challenges = Challenge.query \
        .filter(Challenge.expiration_time <= now) \
        .order_by(Challenge.expiration_time.desc()) \
        .all()

    return render_template(
        'dashboard.html',
        title='Home',
        catches=catches,
        catches_per_user=catches_per_user,
        rankings=rankings,
        finished_challenges=finished_challenges  # Pass the finished challenges
    )


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
            process_expired_challenges()
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
    my_catches = Catch.query.filter_by(user_id=current_user.id).order_by(Catch.timestamp.desc()).all()
    my_challenges = ChallengeParticipation.query.filter_by(user_id=current_user.id).all()
    now = datetime.utcnow()
    return render_template("account.html", title="Konto", my_catches=my_catches, my_challenges=my_challenges, now=now)


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
            worth=form.worth.data,  # New field for challenge points
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
    
    # Populate the fish choices from the updated Fish model
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
        
        # Get fish parameters
        multiplicator = selected_fish.multiplicator
        kapital = selected_fish.above_average  # This is our threshold for "under kapital"
        monster = selected_fish.monster
        
        if length < kapital:
            points = length * multiplicator
        elif kapital <= length < monster:
            points = 150
        elif length >= monster:
            points = 300
        else:
            points = 0  # Fallback (shouldn't be reached)

        
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
        fish.worth = form.worth.data
        db.session.commit()
        flash(f'Die Werte von "{fish.name}" wurden erfolgreich aktualisiert.', 'success')
        return redirect(url_for('main.manage_fish'))
    
    elif request.method == 'GET':
        form.multiplicator.data = fish.multiplicator
        form.above_average.data = fish.above_average
        form.monster.data = fish.monster
        form.worth.data = fish.worth

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

@main.route("/challenges")
@login_required
def challenges():
    # Process expired challenges if necessary
    process_expired_challenges()
    
    now = datetime.utcnow()
    current_challenges = Challenge.query.filter(Challenge.expiration_time > now).all()
    expired_challenges = Challenge.query.filter(Challenge.expiration_time <= now).all()
    my_participations = ChallengeParticipation.query.filter_by(user_id=current_user.id).all()
    
    return render_template('challenges.html', title="Herausforderungen",
                           current_challenges=current_challenges,
                           expired_challenges=expired_challenges,
                           my_participations=my_participations,
                           now=now)


@main.route("/create_challenge", methods=['GET', 'POST'])
@login_required
def create_challenge():
    form = CreateChallengeForm()
    # Populate fish choices: "0" means all fish, then each fish is selectable
    fishes = Fish.query.all()
    form.fish.choices = [("0", "Alle Fische")] + [(str(fish.id), fish.name) for fish in fishes]

    if form.validate_on_submit():
        # Determine the expiration based on the time_limit field.
        if form.time_limit.data == "2 minute":
            expiration = datetime.utcnow() + timedelta(minutes=2)
        elif form.time_limit.data == "1 day":
            expiration = datetime.utcnow() + timedelta(days=1)
        elif form.time_limit.data == "1 week":
            expiration = datetime.utcnow() + timedelta(weeks=1)
        elif form.time_limit.data == "1 month":
            expiration = datetime.utcnow() + timedelta(days=30)
        else:
            expiration = datetime.utcnow() + timedelta(weeks=1)  # default

        # If "0" is selected, set fish_id to None.
        fish_id = None
        if form.fish.data != "0":
            fish_id = int(form.fish.data)

        # Create the challenge using the correct field (user_id)
        challenge = Challenge(
            user_id=current_user.id,
            fish_id=fish_id,
            goal=form.goal.data,
            expiration_time=expiration,
            description=form.description.data
        )
        db.session.add(challenge)
        db.session.commit()

        flash("Herausforderung wurde erfolgreich erstellt.", "success")
        return redirect(url_for("main.challenges"))
    
    return render_template("create_challenge.html", title="Challenge erstellen", form=form)

@main.route("/join_challenge/<int:challenge_id>")
@login_required
def join_challenge(challenge_id):
    # Retrieve the challenge or return 404 if not found
    challenge = Challenge.query.get_or_404(challenge_id)
    
    # Check if the current user already joined this challenge
    participation = ChallengeParticipation.query.filter_by(
        challenge_id=challenge_id, user_id=current_user.id
    ).first()
    
    if participation:
        flash("Du bist bereits dieser Challenge beigetreten.", "info")
    else:
        # Create a new participation record for the current user
        new_participation = ChallengeParticipation(
            challenge_id=challenge_id,
            user_id=current_user.id
        )
        db.session.add(new_participation)
        db.session.commit()
        flash("Du bist der Challenge beigetreten!", "success")
    
    return redirect(url_for("main.challenges"))


def process_expired_challenges():
    now = datetime.utcnow()
    # Only get challenges that have expired and have not been processed yet.
    expired_challenges = Challenge.query.filter(
        Challenge.expiration_time <= now,
        Challenge.processed == False
    ).all()

    for challenge in expired_challenges:
        # Calculate full potential points based on the challenge goal.
        if challenge.fish:
            full_points = challenge.goal * challenge.fish.worth
        else:
            full_points = challenge.goal * 25

        for participation in challenge.participations:
            # Query the catches for this participant during the challenge period.
            catch_query = Catch.query.filter(
                Catch.user_id == participation.user_id,
                Catch.timestamp >= challenge.start_time,
                Catch.timestamp <= challenge.expiration_time
            )
            if challenge.fish_id:
                catch_query = catch_query.filter(Catch.fish_id == challenge.fish_id)
            catch_count = catch_query.count()

            if catch_count >= challenge.goal:
                participation.awarded_points = full_points
                participation.success = True
            else:
                participation.awarded_points = -(full_points / 2)
                participation.success = False

            db.session.add(participation)
        
        # Mark this challenge as processed.
        challenge.processed = True
        db.session.add(challenge)
    
    db.session.commit()
