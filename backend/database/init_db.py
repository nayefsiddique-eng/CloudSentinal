from backend.database.database import Base, engine
from backend.database import models

print("Creating database tables...")

Base.metadata.create_all(bind=engine)

print("Database tables created successfully!")