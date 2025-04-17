# app/routes.py

from functools import wraps
from flask import Blueprint, render_template, url_for, flash, redirect, request, abort
from app.forms import (
    ChangeUsernameForm, RegistrationForm, LoginForm,
    AddFishForm, DeleteFishForm, FangmeldungForm,
    EditFishForm, GenerateInviteForm, CreateChallengeForm
)
from app.models import (
    ChallengeCondition, ChallengeParticipation, User,
    Fish, Catch, Invitation, Challenge
)
from app import db, bcrypt, limiter
from flask_login import login_user, current_user, logout_user, login_required
from sqlalchemy import func
from datetime import datetime, timedelta

main = Blueprint('main', __name__)


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Du hast keine Berechtigung, auf diese Seite zuzugreifen.', 'danger')
            return redirect(url_for('main.home'))
        return f(*args, **kwargs)
    return decorated_function


@main.route("/")
@main.route("/home")
def home():
    now = datetime.utcnow()
    catches = Catch.query.order_by(Catch.timestamp.desc()).all()
    catches_per_user = (
        Catch.query.filter_by(user_id=current_user.id)
        .order_by(Catch.timestamp.desc()).all()
        if current_user.is_authenticated else []
    )

    catch_subq = (
        db.session.query(
            Catch.user_id,
            func.coalesce(func.sum(Catch.points), 0).label('catch_points')
        )
        .group_by(Catch.user_id)
        .subquery()
    )
    challenge_subq = (
        db.session.query(
            ChallengeParticipation.user_id,
            func.coalesce(func.sum(ChallengeParticipation.awarded_points), 0)
                .label('challenge_points')
        )
        .join(Challenge, Challenge.id == ChallengeParticipation.challenge_id)
        .group_by(ChallengeParticipation.user_id)
        .subquery()
    )
    rankings = (
        db.session.query(
            User.username,
            (
                func.coalesce(catch_subq.c.catch_points, 0)
                + func.coalesce(challenge_subq.c.challenge_points, 0)
            ).label('total_points')
        )
        .outerjoin(catch_subq, catch_subq.c.user_id == User.id)
        .outerjoin(challenge_subq, challenge_subq.c.user_id == User.id)
        .order_by((func.coalesce(catch_subq.c.catch_points, 0)
                   + func.coalesce(challenge_subq.c.challenge_points, 0))
                  .desc())
        .all()
    )

    process_expired_participations()
    expired_parts = ChallengeParticipation.query.filter_by(processed=True).all()
    expired_dict = {}
    for part in expired_parts:
        entry = expired_dict.setdefault(
            part.challenge_id,
            {"challenge": part.challenge, "participations": []}
        )
        entry["participations"].append(part)
    expired_grouped = list(expired_dict.values())

    return render_template(
        'home.html',
        title='Home',
        catches=catches,
        catches_per_user=catches_per_user,
        rankings=rankings,
        expired_challenges=expired_grouped,
        now=now
    )


# Authentication

@main.route("/register", methods=['GET', 'POST'])
@limiter.limit("10 per hour")
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        invitation = Invitation.query.filter_by(
            code=form.invite_code.data, is_used=False
        ).first()
        if invitation and invitation.email == form.email.data:
            if invitation.expires_at < datetime.utcnow():
                flash('Der Einladungscode ist abgelaufen.', 'danger')
                return redirect(url_for('main.register'))
            hashed = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(username=form.username.data,
                        email=form.email.data,
                        password=hashed)
            db.session.add(user)
            invitation.is_used = True
            db.session.commit()
            flash('Dein Konto wurde erstellt! Du kannst dich jetzt einloggen.', 'success')
            return redirect(url_for('main.login'))
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
            process_expired_participations()
            next_page = request.args.get('next')
            flash('Du wurdest erfolgreich eingeloggt!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('main.home'))
        flash('Login fehlgeschlagen. Bitte überprüfe E-Mail und Passwort.', 'danger')
    return render_template('login.html', title='Login', form=form)


@main.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('main.home'))


# Account

@main.route("/account")
@login_required
def account():
    my_catches = (
        Catch.query.filter_by(user_id=current_user.id)
        .order_by(Catch.timestamp.desc()).all()
    )
    my_challenges = ChallengeParticipation.query.filter_by(
        user_id=current_user.id
    ).all()
    now = datetime.utcnow()
    return render_template(
        "account.html",
        title="Konto",
        my_catches=my_catches,
        my_challenges=my_challenges,
        now=now
    )


@main.route("/account/username", methods=["GET", "POST"])
@login_required
def change_username():
    form = ChangeUsernameForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        db.session.commit()
        flash("Dein Benutzername wurde aktualisiert!", "success")
        return redirect(url_for("main.account"))
    if request.method == "GET":
        form.username.data = current_user.username
    return render_template(
        "change_username.html",
        title="Benutzernamen ändern",
        form=form
    )


# Catches

@main.route('/fangmeldung', methods=['GET', 'POST'])
@login_required
def fangmeldung():
    form = FangmeldungForm()
    fishes = Fish.query.order_by(Fish.name).all()
    form.fish.choices = [(fish.id, fish.name) for fish in fishes]
    catches_per_user = (
        Catch.query.filter_by(user_id=current_user.id)
        .order_by(Catch.timestamp.desc()).all()
        if current_user.is_authenticated else []
    )
    if not fishes:
        flash('Keine Fische verfügbar. Bitte kontaktiere den Administrator.', 'warning')
        return redirect(url_for('main.home'))
    if form.validate_on_submit():
        selected = Fish.query.get(form.fish.data)
        if not selected:
            flash('Der ausgewählte Fisch existiert nicht.', 'danger')
            return redirect(url_for('main.fangmeldung'))
        length = form.length.data
        mult = selected.multiplicator
        avg = selected.above_average
        mon = selected.monster

        pts = length * mult
        if length < avg:
            add = pts
        elif avg <= length < mon:
            add = pts + 150
        else:
            add = pts + 300

        new = Catch(
            length=length,
            fish_id=selected.id,
            user_id=current_user.id,
            points=add
        )
        db.session.add(new)
        db.session.commit()
        flash(
            f'Dein Fang von {int(length)} cm für "{selected.name}" '
            f'wurde erfasst. Vergabene Punkte: {int(add)}.',
            'success'
        )
        return redirect(url_for('main.fangmeldung'))
    return render_template(
        'fangmeldung.html',
        title='Fangmeldung',
        form=form,
        catches_per_user=catches_per_user
    )


@main.route('/delete_catch/<int:catch_id>', methods=['POST'])
@login_required
def delete_catch(catch_id):
    catch = Catch.query.get_or_404(catch_id)
    if catch.user_id != current_user.id:
        abort(403)
    db.session.delete(catch)
    db.session.commit()
    flash('Dein Fang wurde erfolgreich gelöscht.', 'success')
    return redirect(url_for('main.fangmeldung'))


# Fishes (Admin)

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
            type=form.type.data
        )
        db.session.add(fish)
        db.session.commit()
        flash(f'Fisch "{form.name.data}" wurde hinzugefügt.', 'success')
        return redirect(url_for('main.admin_panel'))
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
            return redirect(url_for('main.admin_panel'))
        if fish.catches:
            flash(
                'Dieser Fisch kann nicht gelöscht werden, '
                'da er zugehörige Fänge hat.',
                'danger'
            )
            return redirect(url_for('main.admin_panel'))
        db.session.delete(fish)
        db.session.commit()
        flash(f'Fisch "{form.name.data}" wurde gelöscht.', 'success')
        return redirect(url_for('main.admin_panel'))
    return render_template('delete_fish.html', title='Fisch löschen', form=form)


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
        fish.type = form.type.data
        db.session.commit()
        flash(
            f'Die Werte von "{fish.name}" '
            'wurden erfolgreich aktualisiert.',
            'success'
        )
        return redirect(url_for('main.admin_panel'))
    if request.method == 'GET':
        form.multiplicator.data = fish.multiplicator
        form.above_average.data = fish.above_average
        form.monster.data = fish.monster
        form.type.data = fish.type
    return render_template(
        'edit_fish.html',
        title='Fisch bearbeiten',
        form=form,
        fish=fish
    )


@main.route("/admin/admin_panel")
@login_required
@admin_required
def admin_panel():
    fishes = Fish.query.all()
    challenges = Challenge.query.all()
    return render_template(
        'admin_panel.html',
        title='Admin Panel',
        fishes=fishes,
        challenges=challenges
    )


@main.route("/manage_invitations", methods=['GET', 'POST'])
@login_required
@admin_required
def manage_invitations():
    form = GenerateInviteForm()
    if form.validate_on_submit():
        code = Invitation.generate_unique_code()
        invitation = Invitation(email=form.email.data, code=code)
        db.session.add(invitation)
        db.session.commit()
        flash(f'Einladungscode für {form.email.data}: {code}', 'success')
        return redirect(url_for('main.manage_invitations'))
    invitations = Invitation.query.order_by(Invitation.created_at.desc()).all()
    return render_template(
        'manage_invitations.html',
        title='Einladungen verwalten',
        form=form,
        invitations=invitations
    )


@main.route("/rules")
@login_required
def rules():
    fishes = Fish.query.order_by(Fish.name.asc()).all()
    return render_template('rules.html', title='Regeln', fishes=fishes)


# Challenges

@main.route("/challenges")
@login_required
def challenges():
    process_expired_participations()
    now = datetime.utcnow()

    expired_parts = ChallengeParticipation.query.filter_by(processed=True).all()
    expired_dict = {}
    for part in expired_parts:
        entry = expired_dict.setdefault(
            part.challenge_id,
            {"challenge": part.challenge, "participations": []}
        )
        entry["participations"].append(part)
    expired_grouped = list(expired_dict.values())

    current_challenges = Challenge.query.filter_by(active=True).all()
    my_participations = ChallengeParticipation.query.filter_by(
        user_id=current_user.id
    ).all()

    return render_template(
        'challenges.html',
        title="Herausforderungen",
        current_challenges=current_challenges,
        expired_challenges=expired_grouped,
        my_participations=my_participations,
        now=now
    )


@main.route("/create_challenge", methods=['GET', 'POST'])
@login_required
def create_challenge():
    form = CreateChallengeForm()
    fishes = Fish.query.all()
    fish_choices = [(fish.id, fish.name) for fish in fishes]
    for cond_form in form.conditions:
        cond_form.fish.choices = fish_choices

    if form.validate_on_submit():
        time_limit_map = {
            "2 minute": "T",
            "1 day":    "D",
            "1 week":   "W",
            "1 month":  "M"
        }
        period = time_limit_map.get(form.time_limit.data, "W")
        challenge = Challenge(
            user_id=current_user.id,
            description=form.description.data,
            time_period=period
        )
        db.session.add(challenge)
        db.session.commit()

        for entry in form.conditions.entries:
            cond_type = entry.form.condition_type.data
            goal = entry.form.goal.data
            amount = entry.form.amount.data
            fish_id = entry.form.fish.data if cond_type == 'specific' else None
            fish_type = (
                entry.form.fish_type.data if cond_type == 'category' else None
            )
            new_cond = ChallengeCondition(
                challenge_id=challenge.id,
                condition_type=cond_type,
                goal=goal,
                amount=amount,
                fish_id=fish_id,
                fish_type=fish_type
            )
            db.session.add(new_cond)
        db.session.commit()
        flash("Herausforderung wurde erfolgreich erstellt.", "success")
        return redirect(url_for("main.admin_panel"))
    return render_template(
        "create_challenge.html",
        title="Challenge erstellen",
        form=form
    )


@main.route("/join_challenge/<int:challenge_id>")
@login_required
def join_challenge(challenge_id):
    challenge = Challenge.query.get_or_404(challenge_id)
    participation = ChallengeParticipation.query.filter_by(
        challenge_id=challenge_id,
        user_id=current_user.id
    ).first()

    if participation:
        flash("Du bist bereits dieser Challenge beigetreten.", "info")
    else:
        joined = datetime.utcnow()
        duration_map = {
            'M': timedelta(days=30),
            'W': timedelta(weeks=1),
            'D': timedelta(days=1),
            'T': timedelta(minutes=2)
        }
        dur = duration_map.get(challenge.time_period, timedelta(days=1))
        expiry = joined + dur
        new_part = ChallengeParticipation(
            challenge_id=challenge_id,
            user_id=current_user.id,
            joined_at=joined,
            participation_expiration=expiry
        )
        db.session.add(new_part)
        db.session.commit()
        flash("Du bist der Challenge beigetreten!", "success")

    return redirect(url_for("main.challenges"))


@main.route("/admin/challenge/<int:challenge_id>/deactivate", methods=['POST'])
@login_required
@admin_required
def deactivate_challenge(challenge_id):
    challenge = Challenge.query.get_or_404(challenge_id)
    if challenge.active:
        challenge.active = False
        db.session.commit()
        flash("Challenge deactivated successfully.", "success")
    else:
        flash("Challenge is already inactive.", "info")
    return redirect(url_for('main.admin_panel'))


@main.route("/admin/challenge/<int:challenge_id>/activate", methods=['POST'])
@login_required
@admin_required
def activate_challenge(challenge_id):
    challenge = Challenge.query.get_or_404(challenge_id)
    if not challenge.active:
        challenge.active = True
        db.session.commit()
        flash("Challenge activated successfully.", "success")
    else:
        flash("Challenge is already active.", "info")
    return redirect(url_for('main.admin_panel'))


def process_expired_participations():
    now = datetime.utcnow()
    parts = ChallengeParticipation.query.filter_by(processed=False).all()
    for part in parts:
        challenge = part.challenge
        conditions_met = True
        for cond in challenge.conditions:
            q = Catch.query.filter(
                Catch.user_id == part.user_id,
                Catch.timestamp >= part.joined_at,
                Catch.timestamp <= now
            )
            if cond.condition_type == "specific":
                q = q.filter(Catch.fish_id == cond.fish_id)
            elif cond.condition_type == "category":
                q = q.join(Fish).filter(Fish.type == cond.fish_type)
            if q.count() < cond.goal:
                conditions_met = False
                break

        if conditions_met:
            total_points = sum(c.amount for c in challenge.conditions)
            part.awarded_points = total_points
            part.success = True
            part.processed = True
            db.session.add(part)
        elif now >= part.participation_expiration:
            total_points = sum(c.amount for c in challenge.conditions)
            part.awarded_points = -(total_points / 2)
            part.success = False
            part.processed = True
            db.session.add(part)
    db.session.commit()
