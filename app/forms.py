# app/forms.py

from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, FloatField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, NumberRange
from app.models import User, Fish, Invitation

class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('E-Mail',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Passwort',
                             validators=[DataRequired()])
    confirm_password = PasswordField('Passwort bestätigen',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Registrieren')

    # Custom validators to check for existing username and email
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Der Username ist bereits vergeben. Wähle einen anderen.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Die E-Mail Adresse ist bereits registriert. Wähle eine andere.')

class LoginForm(FlaskForm):
    email = StringField('E-Mail',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password',
                             validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class AddFishForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=50)])
    avg_length = FloatField('Durschnittliche Größe', validators=[DataRequired(), NumberRange(min=0)])
    lower_bound = FloatField('Minimale Größe', validators=[DataRequired(), NumberRange(min=0)])
    upper_bound = FloatField('Maximale Größe', validators=[DataRequired(), NumberRange(min=0)])
    is_rare = BooleanField('Selten', default=False)  
    submit = SubmitField('Fisch hinzufügen')

    def validate_name(self, name):
        fish = Fish.query.filter_by(name=name.data).first()
        if fish:
            raise ValidationError('This fish already exists. Please choose a different name.')
    
    def validate(self, extra_validators=None):
        # First, run the default validations
        if not super(AddFishForm, self).validate(extra_validators):
            return False

        # Cross-field validation: Ensure that upper_bound >= lower_bound
        if self.upper_bound.data <= self.lower_bound.data:
            self.upper_bound.errors.append('Die maximale Größe kann nicht kleiner oder gleich als die minimale Größe sein.')
            return False

        # Cross-field validation: Ensure that avg_length is between lower_bound and upper_bound
        if not (self.lower_bound.data < self.avg_length.data < self.upper_bound.data):
            self.avg_length.errors.append('Die durchschnittliche Größe muss zwischen der minimalen und maximalen Größe liegen.')
            return False

        return True

class DeleteFishForm(FlaskForm):
    name = StringField('Fish Name', validators=[DataRequired(), Length(min=2, max=50)])
    submit = SubmitField('Delete Fish')

    def validate_name(self, name):
        fish = Fish.query.filter_by(name=name.data).first()
        if not fish:
            raise ValidationError('Fish not found.')
               
class FangmeldungForm(FlaskForm):
    fish = SelectField('Fisch', coerce=int, validators=[DataRequired()])
    length = FloatField('Größe des Fisches', validators=[DataRequired(), NumberRange(min=0)])
    submit = SubmitField('Fang melden')
    
class EditFishForm(FlaskForm):
    lower_bound = FloatField('Minimale Größe (cm)', validators=[DataRequired(), NumberRange(min=0)])
    avg_length = FloatField('Durchschnittliche Größe (cm)', validators=[DataRequired(), NumberRange(min=0)])
    upper_bound = FloatField('Maximale Größe (cm)', validators=[DataRequired(), NumberRange(min=0)])
    is_rare = BooleanField('Selten')
    submit = SubmitField('Änderungen speichern')

    def validate_upper_bound(self, upper_bound):
        if upper_bound.data < self.avg_length.data:
            raise ValidationError('Die maximale Größe muss größer oder gleich der durchschnittlichen Größe sein.')

    def validate_avg_length(self, avg_length):
        if avg_length.data < self.lower_bound.data:
            raise ValidationError('Die durchschnittliche Größe muss größer oder gleich der minimalen Größe sein.')
        
class GenerateInviteForm(FlaskForm):
    email = StringField('E-Mail', validators=[DataRequired(), Email()])
    submit = SubmitField('Einladung generieren')

    def validate_email(self, email):
        existing_invitation = Invitation.query.filter_by(email=email.data, is_used=False).first()
        if existing_invitation:
            raise ValidationError('Es existiert bereits eine nicht verwendete Einladung für diese E-Mail-Adresse.')