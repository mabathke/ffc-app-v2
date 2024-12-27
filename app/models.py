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
    avg_length = db.Column(db.Integer, nullable=False)
    lower_bound = db.Column(db.Integer, nullable=False)
    upper_bound = db.Column(db.Integer, nullable=False)
    is_rare = db.Column(db.Boolean, default=False) 
    catches = db.relationship('Catch', backref='fish', lazy=True)

    def __repr__(self):
        return f"Fish('{self.name}', Avg Length={self.avg_length} cm, Lower Bound={self.lower_bound}, Upper Bound= {self.upper_bound})"
    
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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(days=30))  # Optional expiration

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