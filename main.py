import os

from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship

import details
from forms import *

app = Flask(__name__)
# app.config['SECRET_KEY'] = details.secret_key
app.config['SECRET_KEY'] = os.environ.get("TASKS_WEBSITE_KEY")
Bootstrap(app)

# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///taskList.db'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("TASKS_WEBSITE_DATABASE_URL", 'sqlite:///taskList.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    user_name = db.Column(db.String(100))
    taskLists = relationship("TaskList", back_populates="user")


class TaskList(db.Model):
    __tablename__ = "taskLists"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    list_name = db.Column(db.String(250))
    user = relationship("User", back_populates="taskLists")
    tasks_list = relationship("Task", back_populates="list_of_tasks")


class Task(db.Model):
    __tablename__ = "tasks"
    id = db.Column(db.Integer, primary_key=True)
    taskList_id = db.Column(db.Integer, db.ForeignKey("taskLists.id"))
    task_name = db.Column(db.String(250))
    task_completed = db.Column(db.Boolean, default=False, nullable=False)
    list_of_tasks = relationship("TaskList", back_populates="tasks_list")


db.create_all()


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.route("/")
def home():
    if current_user.is_authenticated:
        task_lists = TaskList.query.filter_by(user_id=current_user.id)
    else:
        task_lists = None
    return render_template("index.html", task_lists=task_lists)


@app.route("/add-task-list", methods=["GET", "POST"])
@login_required
def add_task_list():
    form = AddTaskListForm()
    if form.btn_cancel.data:
        return redirect(url_for('home'))
    if form.validate_on_submit():
        new_task_list = TaskList(
            user_id=current_user.id,
            list_name=form.taskListName.data
        )
        db.session.add(new_task_list)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template("add_task_list.html", form=form)


@app.route("/add-task/<int:task_list_id>", methods=["GET", "POST"])
@login_required
def add_task(task_list_id):
    tasks = Task.query.filter_by(taskList_id=task_list_id)
    task_list = TaskList.query.filter_by(id=task_list_id)
    try:
        if task_list[0].user_id != current_user.id:
            return redirect(url_for('home'))
    except IndexError:
        return redirect(url_for('home'))
    form = AddTaskForm()
    task_form = TaskForm()
    if form.btn_cancel.data:
        return redirect(url_for('home'))
    if form.validate_on_submit():
        new_task = Task(
            task_name=form.taskName.data,
            taskList_id=task_list_id
        )
        db.session.add(new_task)
        db.session.commit()
        # return redirect(url_for('home'))
        return redirect(url_for("add_task", form=form, task_form=task_form, task_list_id=task_list_id,
                                task_list_name=task_list[0].list_name, tasks=tasks))
    return render_template("add_task.html", form=form, task_form=task_form, task_list_id=task_list_id,
                           task_list_name=task_list[0].list_name, tasks=tasks)


@app.route("/toggle-task/<int:task_id>", methods=["GET", "POST"])
@login_required
def toggle_task(task_id):
    task = Task.query.filter_by(id=task_id)
    task = task[0]
    task_list = TaskList.query.filter_by(id=task.taskList_id)
    try:
        if task_list[0].user_id != current_user.id:
            return redirect(url_for('home'))
    except IndexError:
        return redirect(url_for('home'))
    if task.task_completed:
        task.task_completed = False
    else:
        task.task_completed = True
    db.session.commit()
    form = AddTaskForm()
    task_form = TaskForm()
    tasks = Task.query.filter_by(taskList_id=task.taskList_id)
    task_list = TaskList.query.filter_by(id=task.taskList_id)
    return redirect(url_for('add_task', form=form, task_form=task_form, task_list_id=task.taskList_id,
                            task_list_name=task_list[0].list_name, tasks=tasks))


@app.route("/delete-task/<int:task_id>", methods=["GET", "POST"])
@login_required
def delete_task(task_id):
    task = Task.query.filter_by(id=task_id)
    try:
        task = task[0]
        task_list = TaskList.query.filter_by(id=task.taskList_id)
        if task_list[0].user_id != current_user.id:
            return redirect(url_for('home'))
    except IndexError:
        return redirect(url_for('home'))
    db.session.delete(task)
    db.session.commit()
    form = AddTaskForm()
    task_form = TaskForm()
    tasks = Task.query.filter_by(taskList_id=task.taskList_id)
    task_list = TaskList.query.filter_by(id=task.taskList_id)
    return redirect(url_for('add_task', form=form, task_form=task_form, task_list_id=task.taskList_id,
                            task_list_name=task_list[0].list_name, tasks=tasks))


@app.route("/delete-task-list/<int:task_list_id>", methods=["GET", "POST"])
@login_required
def delete_task_list(task_list_id):
    task_list = TaskList.query.filter_by(id=task_list_id)
    try:
        task_list = task_list[0]
        if task_list.user_id != current_user.id:
            return redirect(url_for('home'))
    except IndexError:
        return redirect(url_for('home'))
    tasks_to_delete = Task.query.filter_by(taskList_id=task_list_id)
    for task in tasks_to_delete:
        db.session.delete(task)
    db.session.delete(task_list)
    db.session.commit()
    return redirect(url_for('home'))


@app.route('/register', methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegisterForm()
    if form.btn_cancel.data:
        return redirect(url_for('home'))
    if form.validate_on_submit():
        user_email = form.email.data
        email_exists = User.query.filter_by(email=user_email).first()
        if email_exists:
            flash("You've already signed up with this email, log in instead!")
            return redirect(url_for('login'))
        else:
            hashed_password = generate_password_hash(form.password.data,
                                                     method='pbkdf2:sha256',
                                                     salt_length=8)
            new_user = User(
                email=form.email.data,
                password=hashed_password,
                user_name=form.user_name.data,
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            flash('Thank you for registering!')
            return redirect(url_for('home'))
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.btn_cancel.data:
        return redirect(url_for('home'))
    if form.register.data:
        return redirect(url_for('register'))
    if form.validate_on_submit():
        user_email = form.email.data
        user = User.query.filter_by(email=user_email).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=True)
                # flash('You were successfully logged in')
                return redirect(url_for('home'))
            else:
                flash('Password incorrect. Please try again.')
                return redirect(url_for('login'))
        else:
            flash("User doesn't exist. Please register first.")
            return redirect(url_for('login'))
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route("/delete-user-prelim", methods=["GET", "POST"])
@login_required
def delete_user_prelim():
    return render_template("delete_user.html")


@app.route("/delete-user/<int:user_id>", methods=["GET", "POST"])
@login_required
def delete_user(user_id):
    user_to_delete = User.query.filter_by(id=user_id)
    try:
        user_to_delete = user_to_delete[0]
        if user_to_delete.id != current_user.id:
            return redirect(url_for('home'))
    except IndexError:
        return redirect(url_for('home'))
    task_lists_to_delete = TaskList.query.filter_by(user_id=user_to_delete.id)
    tasks_to_delete = []
    for task_list in task_lists_to_delete:
        tasks_to_delete += Task.query.filter_by(taskList_id=task_list.id)
    for task in tasks_to_delete:
        db.session.delete(task)
    for task_list in task_lists_to_delete:
        db.session.delete(task_list)
    db.session.delete(user_to_delete)
    db.session.commit()
    flash(f'{user_to_delete.user_name} user and all data were successfully deleted')
    return redirect(url_for('logout'))


if __name__ == '__main__':
    app.run(debug=True)
