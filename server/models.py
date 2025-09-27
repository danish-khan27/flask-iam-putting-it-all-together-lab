from sqlalchemy.orm import validates, relationship
from sqlalchemy.ext.hybrid import hybrid_property
from marshmallow import Schema, fields, validates_schema, ValidationError

from config import db, bcrypt


# ====================
# MODELS
# ====================

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    _password_hash = db.Column(db.String, nullable=False)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    # Relationship → a User has many Recipes
    recipes = relationship("Recipe", backref="user", lazy=True)

    # Protect direct access to password_hash
    @hybrid_property
    def password_hash(self):
        raise AttributeError("Password hashes are not viewable.")

    # Set password_hash using bcrypt
    @password_hash.setter
    def password_hash(self, password):
        self._password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    # Authenticate user with password
    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password)

    def __repr__(self):
        return f"<User {self.username}, id={self.id}>"


class Recipe(db.Model):
    __tablename__ = 'recipes'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer, nullable=False)

    # Foreign key → belongs to User
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    # Validations
    @validates("title")
    def validate_title(self, key, value):
        if not value or value.strip() == "":
            raise ValueError("Title is required.")
        return value

    @validates("instructions")
    def validate_instructions(self, key, value):
        if not value or len(value.strip()) < 50:
            raise ValueError("Instructions must be at least 50 characters long.")
        return value

    def __repr__(self):
        return f"<Recipe {self.title}, id={self.id}>"


# ====================
# SCHEMAS
# ====================

class UserSchema(Schema):
    id = fields.Int()
    username = fields.Str()
    image_url = fields.Str()
    bio = fields.Str()


class RecipeSchema(Schema):
    id = fields.Int()
    title = fields.Str()
    instructions = fields.Str()
    minutes_to_complete = fields.Int()
    user = fields.Nested(UserSchema)
