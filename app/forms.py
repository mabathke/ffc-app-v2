# app/forms.py

from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, FloatField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, NumberRange
from app.models import User, Fish

class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password',
                             validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    # Custom validators to check for existing username and email
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password',
                             validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class AddFishForm(FlaskForm):
    name = StringField('Fish Name', validators=[DataRequired(), Length(min=2, max=50)])
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