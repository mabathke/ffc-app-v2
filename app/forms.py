# app/forms.py

from flask_wtf import FlaskForm
from wtforms import (
    StringField, SelectField, FloatField, PasswordField, SubmitField,
    BooleanField, IntegerField, TextAreaField, FieldList, FormField
)
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, NumberRange
from app.models import User, Fish, Invitation


# === Authentication & Account Forms ===

class RegistrationForm(FlaskForm):
    invite_code = StringField(
        'Einladungscode',
        validators=[
            DataRequired(),
            Length(min=6, max=6, message="Der Einladungscode muss 6 Ziffern lang sein.")
        ]
    )
    email = StringField('E-Mail', validators=[DataRequired(), Email()])
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Passwort', validators=[DataRequired()])
    confirm_password = PasswordField(
        'Passwort bestätigen',
        validators=[DataRequired(), EqualTo('password')]
    )
    submit = SubmitField('Registrieren')

    def validate_invite_code(self, invite_code):
        invitation = Invitation.query.filter_by(code=invite_code.data, is_used=False).first()
        if not invitation:
            raise ValidationError('Ungültiger oder bereits verwendeter Einladungscode.')

    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError('Die E-Mail Adresse ist bereits registriert. Wähle eine andere.')
        invitation = Invitation.query.filter_by(email=email.data, is_used=False).first()
        if not invitation:
            raise ValidationError('Keine gültige Einladung für diese E-Mail-Adresse.')

    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError('Der Username ist bereits vergeben. Wähle einen anderen.')


class LoginForm(FlaskForm):
    email = StringField('E-Mail', validators=[DataRequired(), Email()])
    password = PasswordField('Passwort', validators=[DataRequired()])
    remember = BooleanField('Angemeldet bleiben')
    submit = SubmitField('Login')


class ChangeUsernameForm(FlaskForm):
    username = StringField(
        "Neuer Benutzername",
        validators=[DataRequired(), Length(min=2, max=50)]
    )
    submit = SubmitField("Ändern")


# === Fish Management Forms ===

class AddFishForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    multiplicator = FloatField('Multiplicator', validators=[DataRequired()])
    above_average = IntegerField('Above Average Length', validators=[DataRequired()])
    monster = IntegerField('Monster Length', validators=[DataRequired()])

    type = SelectField(
        'Fischtyp',
        choices=[('Weißfisch', 'Weißfisch'), ('Raubfisch', 'Raubfisch')],
        validators=[DataRequired()]
    )
    submit = SubmitField('Add Fish')

    def validate_name(self, name):
        if Fish.query.filter_by(name=name.data).first():
            raise ValidationError('Der Fisch existiert bereits.')

    def validate(self, extra_validators=None):
        if not super().validate(extra_validators):
            return False
        if self.monster.data <= self.above_average.data:
            self.monster.errors.append(
                'Die Monster-Länge muss größer als die Above Average Länge sein.'
            )
            return False
        return True


class DeleteFishForm(FlaskForm):
    name = StringField('Fischname', validators=[DataRequired(), Length(min=2, max=50)])
    submit = SubmitField('Fisch löschen')

    def validate_name(self, name):
        if not Fish.query.filter_by(name=name.data).first():
            raise ValidationError('Fisch nicht gefunden.')


class EditFishForm(FlaskForm):
    multiplicator = FloatField('Multiplicator', validators=[DataRequired()])
    above_average = IntegerField('Above Average Length', validators=[DataRequired()])
    monster = IntegerField('Monster Length', validators=[DataRequired()])
    type = SelectField(
        'Fischtyp',
        choices=[('Weißfisch', 'Weißfisch'), ('Raubfisch', 'Raubfisch')],
        validators=[DataRequired()]
    )
    submit = SubmitField('Update Fish')


# === Catch Submission Form ===

class FangmeldungForm(FlaskForm):
    fish = SelectField('Fisch', coerce=int, validators=[DataRequired()])
    length = FloatField('Größe des Fisches', validators=[DataRequired(), NumberRange(min=0)])
    submit = SubmitField('Fang melden')


# === Invitation Form ===

class GenerateInviteForm(FlaskForm):
    email = StringField('E-Mail', validators=[DataRequired(), Email()])
    submit = SubmitField('Einladung generieren')

    def validate_email(self, email):
        if Invitation.query.filter_by(email=email.data, is_used=False).first():
            raise ValidationError(
                'Es existiert bereits eine nicht verwendete Einladung für diese E-Mail-Adresse.'
            )


# === Challenge Creation Forms ===

class ChallengeConditionForm(FlaskForm):
    condition_type = SelectField(
        'Bedingungstyp',
        choices=[
            ('specific', 'Spezifisch'),
            ('category', 'Kategorie'),
            ('any', 'Beliebig')
        ],
        validators=[DataRequired()]
    )
    goal = IntegerField('Ziel: Anzahl Fische', validators=[DataRequired()])
    amount = FloatField('Punkte Wert', validators=[DataRequired()])
    fish = SelectField('Fisch', coerce=int, choices=[])
    fish_type = SelectField(
        'Fischtyp',
        choices=[('Weißfisch', 'Weißfisch'), ('Raubfisch', 'Raubfisch')]
    )

    class Meta:
        csrf = False


class CreateChallengeForm(FlaskForm):
    time_limit = SelectField(
        'Zeitlimit',
        choices=[
            ('2 minute', '2 Minuten'),
            ('1 day', '1 Tag'),
            ('1 week', '1 Woche'),
            ('1 month', '1 Monat')
        ],
        validators=[DataRequired()]
    )
    description = TextAreaField('Beschreibung (optional)')
    conditions = FieldList(
        FormField(ChallengeConditionForm),
        min_entries=1,
        max_entries=5
    )
    submit = SubmitField('Challenge erstellen')
