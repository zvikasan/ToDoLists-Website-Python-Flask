from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField
from wtforms.validators import DataRequired, URL, EqualTo


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()], render_kw={'autofocus': True})
    password = PasswordField("Password", validators=[EqualTo('password_2', message='Passwords must match')])
    password_2 = PasswordField("Repeat Password", validators=[DataRequired()])
    user_name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Register")
    btn_cancel = SubmitField(label='Cancel', render_kw={'formnovalidate': True})


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()], render_kw={'autofocus': True})
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")
    register = SubmitField(label='Register', render_kw={'formnovalidate': True})
    btn_cancel = SubmitField(label='Cancel', render_kw={'formnovalidate': True})


class AddTaskListForm(FlaskForm):
    taskListName = StringField("Name of your Task List", validators=[DataRequired()], render_kw={'autofocus': True})
    submit = SubmitField("Add")
    btn_cancel = SubmitField(label='Cancel', render_kw={'formnovalidate': True})


class AddTaskForm(FlaskForm):
    taskName = StringField("New task:", validators=[DataRequired()], render_kw={'autofocus': True})
    submit = SubmitField("Add Task")
    btn_cancel = SubmitField(label='Back To Lists', render_kw={'formnovalidate': True})


class TaskForm(FlaskForm):
    taskName = StringField("Task")
    task_checkbox = BooleanField()

