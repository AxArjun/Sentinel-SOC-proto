from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField
from wtforms.validators import DataRequired, Email, Length, Regexp, EqualTo

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message="Username is required."),
        Length(min=3, max=50, message="Username must be between 3 and 50 characters."),
        Regexp(r'^[\w.@+-]+$', message="Username must contain only letters, numbers, and @/./+/-/_ characters.")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required."),
        Length(min=8, max=128, message="Password must be at least 8 characters long.")
    ])
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message="Username is required."),
        Length(min=3, max=50, message="Username must be between 3 and 50 characters."),
        Regexp(r'^[\w.@+-]+$', message="Username must contain only letters, numbers, and @/./+/-/_ characters.")
    ])
    email = StringField('Email Address', validators=[
        DataRequired(message="Email address is required."),
        Email(message="Invalid email address format."),
        Length(max=100)
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required."),
        Length(min=12, max=128, message="Password must be at least 12 characters long."),
        Regexp(
            r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$',
            message="Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character."
        )
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message="Please confirm your password."),
        EqualTo('password', message="Passwords must match.")
    ])
    role_id = SelectField('Role Assignment', coerce=int, validators=[
        DataRequired(message="Please select a user role.")
    ])
    submit = SubmitField('Register User')
