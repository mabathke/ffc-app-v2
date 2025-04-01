import os
import sys 

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app, db
from app.models import Invitation

app = create_app()

with app.app_context():
    your_email = "your_email@example.com"  # Replace with your email
    code = Invitation.generate_unique_code()
    invitation = Invitation(email=your_email, code=code)
    db.session.add(invitation)
    db.session.commit()
    print(f"Invitation code for {your_email} is {code}")
