# app/models.py

from app import db, login_manager
from flask_login import UserMixin
from datetime import datetime
import uuid
from datetime import datetime, timedelta
import random
import string

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    __tablename__ = 'user' 
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=True)  # Admin flag

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', Admin={self.is_admin})"

class Fish(db.Model):
    __tablename__ = 'fish'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    multiplicator = db.Column(db.Float, nullable=False, default=1.0)
    above_average = db.Column(db.Integer, nullable=False)
    monster = db.Column(db.Integer, nullable=False)
    worth = db.Column(db.Float, nullable=False, default=25)  # New attribute for challenge points
    catches = db.relationship('Catch', backref='fish', lazy=True)

    def __repr__(self):
        return (f"Fish('{self.name}', multiplicator={self.multiplicator}, "
                f"above_average={self.above_average}, monster={self.monster}, worth={self.worth})")

    
class Catch(db.Model):
    __tablename__ = 'catch'
    id = db.Column(db.Integer, primary_key=True)
    length = db.Column(db.Integer, nullable=False)
    fish_id = db.Column(db.Integer, db.ForeignKey('fish.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    points = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship('User', backref='catches')

    def __repr__(self):
        return f"Catch(Fish ID={self.fish_id}, Length={self.length}, User ID={self.user_id})"
    
class Invitation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    code = db.Column(db.String(6), unique=True, nullable=False)
    is_used = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow())
    expires_at = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(days=7))  

    def __repr__(self):
        return f"Invitation('{self.email}', '{self.code}', Used: {self.is_used})"

    @staticmethod
    def generate_unique_code():
        """Generates a unique 6-digit code."""
        while True:
            code = ''.join(random.choices(string.digits, k=6))
            if not Invitation.query.filter_by(code=code).first():
                break
        return code
    
class Challenge(db.Model):
    __tablename__ = 'challenge'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    fish_id = db.Column(db.Integer, db.ForeignKey('fish.id'), nullable=True)
    goal = db.Column(db.Integer, nullable=False)
    start_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    expiration_time = db.Column(db.DateTime, nullable=False)
    description = db.Column(db.String(255))
    processed = db.Column(db.Boolean, default=False, nullable=False)  # New field

    # Relationships
    user = db.relationship('User', backref='created_challenges')
    fish = db.relationship('Fish')
    participations = db.relationship('ChallengeParticipation', backref='challenge', lazy=True)

    def __repr__(self):
        target = "ALL" if not self.fish_id else self.fish.name
        return f"<Challenge id:{self.id} User:{self.user_id}, Target:{target}, Goal:{self.goal}>"

    
class ChallengeParticipation(db.Model):
    __tablename__ = 'challenge_participation'
    id = db.Column(db.Integer, primary_key=True)
    challenge_id = db.Column(db.Integer, db.ForeignKey('challenge.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    joined_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    awarded_points = db.Column(db.Float, default=0)
    success = db.Column(db.Boolean, default=False)  # True if challenge met, False if not.

    user = db.relationship('User', backref='challenge_participations')

    def __repr__(self):
        return f"<ChallengeParticipation Challenge:{self.challenge_id} User:{self.user_id} Awarded:{self.awarded_points} Success:{self.success}>"
