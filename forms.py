from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField
# from wtforms.validators import DataRequired, EqualTo, Email
from wtforms.fields.html5 import EmailField
from wtforms import validators
# import email_validator


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[validators.DataRequired(), validators.email()], render_kw={'autofocus': True})
    password = PasswordField("Password",
                             validators=[validators.EqualTo('password_2',
                                                            message='Passwords must match')])
    password_2 = PasswordField("Repeat Password", validators=[validators.DataRequired()])
    user_name = StringField("Name", validators=[validators.DataRequired()])
    submit = SubmitField("Register")
    btn_cancel = SubmitField(label='Cancel', render_kw={'formnovalidate': True})


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[validators.DataRequired()],
                        render_kw={'autofocus': True})
    password = PasswordField("Password", validators=[validators.DataRequired()])
    submit = SubmitField("Login")
    register = SubmitField(label='Register', render_kw={'formnovalidate': True})
    forgot_password = SubmitField(label='Forgot Password', render_kw={'formnovalidate': True})
    btn_cancel = SubmitField(label='Cancel', render_kw={'formnovalidate': True})


class ForgotPasswordForm(FlaskForm):
    email = EmailField("Email", validators=[validators.DataRequired(), validators.Email()])
    submit = SubmitField("Send reset link")
    btn_cancel = SubmitField(label='Cancel', render_kw={'formnovalidate': True})


class PasswordResetForm(FlaskForm):
    new_password = PasswordField("New Password",
                                 validators=[validators.EqualTo("new_password2",
                                                                message='Passwords must match')])
    new_password2 = PasswordField("Repeat Password", validators=[validators.DataRequired()])
    submit = SubmitField("Reset Password")
    btn_cancel = SubmitField(label='Cancel', render_kw={'formnovalidate': True})


class AddTaskListForm(FlaskForm):
    taskListName = StringField("Name of your Task List", validators=[validators.DataRequired()], render_kw={'autofocus': True})
    submit = SubmitField("Add")
    btn_cancel = SubmitField(label='Cancel', render_kw={'formnovalidate': True})


class AddTaskForm(FlaskForm):
    taskName = StringField("New task:", validators=[validators.DataRequired()], render_kw={'autofocus': True})
    submit = SubmitField("Add Task")
    btn_cancel = SubmitField(label='Back To Lists', render_kw={'formnovalidate': True})


class TaskForm(FlaskForm):
    taskName = StringField("Task")
    task_checkbox = BooleanField()

