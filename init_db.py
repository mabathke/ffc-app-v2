# init_db.py

import os
from app import create_app, db

# Create the app instance
app = create_app()

# Ensure the instance directory exists
instance_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance')
if not os.path.exists(instance_path):
    os.makedirs(instance_path)
    print(f"Instance directory created at: {instance_path}")
else:
    print(f"Instance directory already exists at: {instance_path}")

# Initialize the database
with app.app_context():
    db.create_all()
    print("Database initialized and tables created.")
