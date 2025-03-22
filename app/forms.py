# app/forms.py

from flask_wtf import FlaskForm
from wtforms import (StringField, SelectField, FloatField, PasswordField, SubmitField,
                        BooleanField, IntegerField, TextAreaField)
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, NumberRange
from app.models import User, Fish, Invitation

class RegistrationForm(FlaskForm):
    invite_code = StringField('Einladungscode', validators=[DataRequired(), Length(min=6, max=6, message="Der Einladungscode muss 6 Ziffern lang sein.")])
    email = StringField('E-Mail', validators=[DataRequired(), Email()])
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Passwort', validators=[DataRequired()])
    confirm_password = PasswordField('Passwort bestätigen', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Registrieren')

    def validate_invite_code(self, invite_code):
        invitation = Invitation.query.filter_by(code=invite_code.data, is_used=False).first()
        if not invitation:
            raise ValidationError('Ungültiger oder bereits verwendeter Einladungscode.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Die E-Mail Adresse ist bereits registriert. Wähle eine andere.')
        invitation = Invitation.query.filter_by(email=email.data, is_used=False).first()
        if not invitation:
            raise ValidationError('Keine gültige Einladung für diese E-Mail-Adresse.')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Der Username ist bereits vergeben. Wähle einen anderen.')

class LoginForm(FlaskForm):
    email = StringField('E-Mail',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Passwort',
                             validators=[DataRequired()])
    remember = BooleanField('Angemeldet bleiben')
    submit = SubmitField('Admin')

class AddFishForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    multiplicator = FloatField('Multiplicator', validators=[DataRequired()])
    above_average = IntegerField('Above Average Length', validators=[DataRequired()])
    monster = IntegerField('Monster Length', validators=[DataRequired()])
    worth = FloatField('Worth', validators=[DataRequired()])
    submit = SubmitField('Add Fish')

    def validate_name(self, name):
        fish = Fish.query.filter_by(name=name.data).first()
        if fish:
            raise ValidationError('Der Fisch existiert bereits.')
    
    def validate(self, extra_validators=None):
        if not super(AddFishForm, self).validate(extra_validators):
            return False
        if self.monster.data <= self.above_average.data:
            self.monster.errors.append('Die Monster-Länge muss größer als die Above Average Länge sein.')
            return False
        return True

class DeleteFishForm(FlaskForm):
    name = StringField('Fischname', validators=[DataRequired(), Length(min=2, max=50)])
    submit = SubmitField('Fisch löschen')

    def validate_name(self, name):
        fish = Fish.query.filter_by(name=name.data).first()
        if not fish:
            raise ValidationError('Fisch nicht gefunden.')
               
class FangmeldungForm(FlaskForm):
    fish = SelectField('Fisch', coerce=int, validators=[DataRequired()])
    length = FloatField('Größe des Fisches', validators=[DataRequired(), NumberRange(min=0)])
    submit = SubmitField('Fang melden')
    
class EditFishForm(FlaskForm):
    multiplicator = FloatField('Multiplicator', validators=[DataRequired()])
    above_average = IntegerField('Above Average Length', validators=[DataRequired()])
    monster = IntegerField('Monster Length', validators=[DataRequired()])
    worth = FloatField('Worth', validators=[DataRequired()])
    submit = SubmitField('Update Fish')

class CreateChallengeForm(FlaskForm):
    # Optional fish selection. "0" means all fish.
    fish = SelectField('Fisch auswählen (optional)', validators=[DataRequired()])
    goal = IntegerField('Ziel: Anzahl Fische fangen', validators=[DataRequired()])
    time_limit = SelectField('Zeitlimit', choices=[
        ('2 minute', '2 Minuten'),  # Testing option
        ('1 day', '1 Tag'),
        ('1 week', '1 Woche'),
        ('1 month', '1 Monat')
    ], validators=[DataRequired()])
    description = TextAreaField('Beschreibung (optional)')
    submit = SubmitField('Challenge erstellen')
        
class GenerateInviteForm(FlaskForm):
    email = StringField('E-Mail', validators=[DataRequired(), Email()])
    submit = SubmitField('Einladung generieren')

    def validate_email(self, email):
        existing_invitation = Invitation.query.filter_by(email=email.data, is_used=False).first()
        if existing_invitation:
            raise ValidationError('Es existiert bereits eine nicht verwendete Einladung für diese E-Mail-Adresse.')