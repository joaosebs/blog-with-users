from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps

from dotenv import load_dotenv
import os

##SETS UP FLASK AND ITS DEPENDANTS
# In Procfile, type "web: gunicorn main:app". This tells gunicorn to look up in main.py where my app is, so it can
# "translate" it into readable stuff by heroku, who will receive it as an http request.
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)
##CONNECT TO DB

# To connect to SQLite database:
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'

#To connect to Heroku Postgres Database, you have to: 1- in the dashboard, request the Postgres add-on.
# 2- Check config vars in Settings. 3- get your code to access that Postgres database, like it is in the environment.
# 4- install the psycopg2-binary in your python code, and add it to the requirements.
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

##STARTUP LOGIN MANAGER
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Define administrator privileges with a decorator function.
# In this current format, the Admin will be the 1st User object registered in the database.
def admin_only(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if current_user.id == 1:
            return function(*args, **kwargs)
        else:

            # If a route has this decorator, and a user or visitor tries to access it by any means (a button
            # left unattended, or directly typing the url), they will be met with a 403 error, Forbidden access.
            return abort(403)

    return wrapper


##CONFIGURE TABLES
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    comment_author = relationship("User", back_populates="comments")
    parent_post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable=False)


db.create_all()


##DEFINING THE ROUTES


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()

    # In most routes, a "current_user" User object is sent in order to format the header, navigation bar,
    # and other website functionalities
    return render_template("index.html", all_posts=posts, current_user=current_user)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():

        # Checks if the user is already registered. If so, reports to login page, with flash message
        if User.query.filter_by(email=form.email.data).first():
            flash("That email address is already registered. Try logging in.")
            return redirect("/login")

        # Adds security to the password the user chose, by storing only a hashed and salted version of it
        hashed = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)

        # Creates a new User object and adds it to the database
        new_user = User(email=form.email.data, password=hashed, name=form.name.data)
        db.session.add(new_user)
        db.session.commit()

        # Logs the newly registered user into the site, and redirects to the homepage
        login_user(new_user)
        return redirect("/")
    return render_template("register.html", form=form, current_user=current_user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        input_password = form.password.data
        requested_user = User.query.filter_by(email=form.email.data).first()

        # Checks if the email is present in the database
        if not requested_user:
            flash("There is no user with that registered email.")
            return redirect(url_for("login"))

        # Checks if the password is the same as the one stored in the database
        if check_password_hash(pwhash=requested_user.password, password=input_password):
            login_user(requested_user)
            return redirect("/")
        else:
            flash("Incorrect password")
            return redirect(url_for("login"))
    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


# This type of routes is edited in the following way:
# 1. The HTML file uses Jinja in an anchor tag to send a {{ url_for('<function_name>', <var_name>=variable) }}
# 2. This route must allow for that type of prompt, by being formatted like so: "/<var_name>" and the function
#    definition must allow for one argument with the same var_name.
@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    # Access the requested post, and all its associated comments
    requested_post = BlogPost.query.get(post_id)
    comments = Comment.query.filter_by(post_id=post_id)
    comment_form = CommentForm()
    if comment_form.validate_on_submit():

        # Checks if the user is logged in before allowing to submit the comment to be saved
        if current_user.is_authenticated:

            # To allow for the full text editor, the "text" property will be filled by the CKEditor,
            # which requires additional code in the HTML file
            new_comment = Comment(text=comment_form.comment.data, comment_author=current_user,
                                  parent_post=requested_post)
            db.session.add(new_comment)
            db.session.commit()
        else:
            flash("You need to be logged in to post a comment.")
            return redirect(url_for("login"))

    return render_template("post.html", post=requested_post, form=comment_form, current_user=current_user,
                           comments=comments)


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", current_user=current_user)


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)

    # The edit-post form uses the same type of form as the create a new one. However, in this manner,
    # it is auto-filled with that post's information, so the user can edit only the relevant parts.
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
