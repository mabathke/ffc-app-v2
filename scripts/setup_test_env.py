import os
import sys 

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app, db, bcrypt
from app.models import User, Fish

app = create_app()

with app.app_context():
    # Create admin user if not already present
    admin_email = "admin@example.com"
    admin_username = "admin"
    admin_password = "password"  # Change this to a secure password if needed

    admin_user = User.query.filter_by(email=admin_email).first()
    if not admin_user:
        hashed_password = bcrypt.generate_password_hash(admin_password).decode('utf-8')
        admin_user = User(
            username=admin_username,
            email=admin_email,
            password=hashed_password,
            is_admin=True
        )
        db.session.add(admin_user)
        db.session.commit()
        print(f"Created admin user: {admin_username} with email {admin_email}")
    else:
        print(f"Admin user already exists: {admin_username}")

    # Fish data as provided
    fish_data = [
        {"name": "Grasskarpfen", "multiplicator": 2.0, "above_average": 70, "monster": 100, "worth": 100, "type": "Weißfisch"},
        {"name": "Ukelai", "multiplicator": 1.9, "above_average": 20, "monster": 25, "worth": 25, "type": "Weißfisch"},
        {"name": "Zander", "multiplicator": 1.8, "above_average": 70, "monster": 85, "worth": 85, "type": "Raubfisch"},
        {"name": "Rapfen", "multiplicator": 1.5, "above_average": 50, "monster": 70, "worth": 70, "type": "Raubfisch"},
        {"name": "Wels", "multiplicator": 1.7, "above_average": 100, "monster": 150, "worth": 150, "type": "Weißfisch"},
        {"name": "Aal", "multiplicator": 1.4, "above_average": 75, "monster": 90, "worth": 90, "type": "Weißfisch"},
        {"name": "Schleie", "multiplicator": 1.5, "above_average": 35, "monster": 50, "worth": 50, "type": "Weißfisch"},
        {"name": "Hecht", "multiplicator": 1.0, "above_average": 80, "monster": 100, "worth": 100, "type": "Raubfisch"},
        {"name": "Schuppenkarpfen", "multiplicator": 1.1, "above_average": 55, "monster": 70, "worth": 70, "type": "Weißfisch"},
        {"name": "Giebel", "multiplicator": 0.5, "above_average": 30, "monster": 45, "worth": 45, "type": "Weißfisch"},
        {"name": "Spiegelkarpfen", "multiplicator": 1.0, "above_average": 60, "monster": 70, "worth": 70, "type": "Weißfisch"},
        {"name": "Flussbarsch", "multiplicator": 1.0, "above_average": 32, "monster": 40, "worth": 40, "type": "Raubfisch"},
        {"name": "Aland", "multiplicator": 0.6, "above_average": 60, "monster": 70, "worth": 70, "type": "Weißfisch"},
        {"name": "Karausche", "multiplicator": 0.6, "above_average": 25, "monster": 35, "worth": 35, "type": "Weißfisch"},
        {"name": "Güster", "multiplicator": 0.4, "above_average": 25, "monster": 35, "worth": 35, "type": "Weißfisch"},
        {"name": "Brasse", "multiplicator": 0.4, "above_average": 60, "monster": 70, "worth": 70, "type": "Weißfisch"},
        {"name": "Rotauge", "multiplicator": 0.3, "above_average": 30, "monster": 40, "worth": 40, "type": "Weißfisch"},
        {"name": "Rotfeder", "multiplicator": 0.3, "above_average": 30, "monster": 40, "worth": 40, "type": "Weißfisch"},
        {"name": "Kaulbarsch", "multiplicator": 0.1, "above_average": 20, "monster": 25, "worth": 25, "type": "Weißfisch"},
        {"name": "Katzenwels", "multiplicator": 0.1, "above_average": 35, "monster": 45, "worth": 45, "type": "Weißfisch"},
        {"name": "Grundel", "multiplicator": 0.1, "above_average": 6, "monster": 10, "worth": 10, "type": "Weißfisch"},
    ]

    # Insert each fish into the database if it doesn't exist
    for data in fish_data:
        fish = Fish.query.filter_by(name=data["name"]).first()
        if not fish:
            fish = Fish(
                name=data["name"],
                multiplicator=data["multiplicator"],
                above_average=data["above_average"],
                monster=data["monster"],
                worth=data["worth"],
                type=data["type"]
            )
            db.session.add(fish)
            print(f"Added fish: {data['name']}")
        else:
            print(f"Fish already exists: {data['name']}")

    db.session.commit()
    print("Setup completed.")
