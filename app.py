from flask import Flask, flash, render_template, url_for, request, redirect
from flask_sqlalchemy import SQLAlchemy, declarative_base
from flask_migrate import Migrate
from datetime import datetime
from forms import UserForm, PasswordForm, PostForm, LoginForm, SearchForm
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, logout_user, current_user, login_required
from flask_ckeditor import CKEditor
from werkzeug.utils import secure_filename
import uuid as uuid
import os

app = Flask(__name__)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:password123@localhost/our_users'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'secret key'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
ckeditor = CKEditor(app)

UPLOAD_FOLDER = 'static/images/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    intro = db.Column(db.String(300), nullable=False)
    slug = db.Column(db.String(255))
    text = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    poster_id = db.Column(db.Integer, db.ForeignKey('users.id'))


class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200), nullable=False, unique=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    password_hash = db.Column(db.String(128))
    profile_picture = db.Column(db.String(500), nullable=True)
    posts = db.relationship('Article', backref='poster')

    @property
    def password(self):
        raise AttributeError('password is not readable!')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<{self.name}>'


    def __repr__(self):
        return f'<Article {self.id}>'


@app.context_processor
def base():
    form = SearchForm()
    return dict(form=form)


@app.route('/admin')
@login_required
def admin():
    if current_user.id == 32:
        return render_template('admin.html')
    else:
        flash('You Don\'t Have Permission To Access Admin Page!')
        return redirect(url_for('dashboard'))


@app.route('/search', methods=['POST'])
def search():
    form = SearchForm()
    if form.validate_on_submit():
        post_searched = form.searched.data
        posts = Article.query.filter(Article.text.like('%' + post_searched + '%'))
        posts = posts.order_by(Article.title)
        return render_template('search.html', form=form, post_searched=post_searched, posts=posts)


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                flash("You've Been Logged In Successfully")
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid Password! Try again!')
        else:
            flash('This User Does\'t Exist')
    return render_template('login.html', form=form)


@app.route('/logout', methods=['POST', 'GET'])
@login_required
def logout():
    logout_user()
    flash('Your Have Been Logged Out!')
    return redirect(url_for('login'))


@app.route('/dashboard', methods=['POST', 'GET'])
@login_required
def dashboard():
    posts = Article.query.filter_by(poster_id=current_user.id)
    return render_template('dashboard.html', posts=posts)


@app.route('/user/delete/<int:id>', methods=['POST', 'GET'])
@login_required
def user_delete(id):
    form = UserForm()
    user_to_delete = Users.query.get_or_404(id)
    if current_user.id == user_to_delete.id:
        try:
            db.session.delete(user_to_delete)
            db.session.commit()
            flash('User Deleted Successfully')
            users = Users.query.order_by(Users.date_added).all()
            return redirect(url_for('login'))
        except:
            flash('Error! Something went wrong...try again')
            users = Users.query.order_by(Users.date_added).all()
            return redirect(url_for('login'))
    else:
        flash('Error! You cannot delete this user...')
        return redirect(url_for('dashboard'))


@app.route('/user/update/<int:id>', methods=['POST', 'GET'])
@login_required
def user_update(id):
    form = UserForm()
    user_to_update = Users.query.get_or_404(id)
    if request.method == 'POST':
        user_to_update.name = request.form['name']
        user_to_update.email = request.form['email']
        user_to_update.username = request.form['username']
        user_to_update.profile_picture = request.files['profile_picture']

        picture_filename = secure_filename(user_to_update.profile_picture.filename)
        picture_name = str(uuid.uuid1()) + '_' + picture_filename
        user_to_update.profile_picture.save(os.path.join(app.config['UPLOAD_FOLDER'], picture_name))
        user_to_update.profile_picture = picture_name


        try:
            db.session.commit()
            flash('User Updated Successfully')
            return redirect(url_for('dashboard'))
        except:
            flash('Error! Something went wrong...try again')
            return redirect(url_for('dashboard'))
    else:
        return render_template('user_update.html', user_to_update=user_to_update, form=form)


@app.route('/user/add', methods=['GET', 'POST'])
def add_user():
    form = UserForm()

    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            hashed_pw = generate_password_hash(form.password_hash.data)
            user = Users(username=form.username.data,
                         name=form.name.data,
                         email=form.email.data,
                         password_hash=hashed_pw)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash('User Added Successfully')
        elif user is not None:
            flash('Such user already exists')

        return redirect(url_for('dashboard'))
    users = Users.query.order_by(Users.date_added).all()
    user = Users.query.filter_by(email=form.email.data).first()

    return render_template('registration.html', form=form, users=users, user=user)


@app.route('/user', methods=['POST', 'GET'])
def user():
    form = PasswordForm()
    email = None
    password = None
    pw_to_check = None
    passed = None

    if form.validate_on_submit():
        email = form.email.data
        password = form.password_hash.data
        pw_to_check = Users.query.filter_by(email=email).first()
        passed = check_password_hash(pw_to_check.password_hash, password)

    return render_template('login.html',form=form, email=email, password=password,
                           pw_to_check=pw_to_check, passed=passed)


@app.route('/')
def index():
    users = Users.query.order_by(Users.date_added)
    return render_template('index.html', users=users)


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/posts')
def posts():
    articles = Article.query.order_by(Article.date.desc()).all()
    return render_template('posts.html', articles=articles)


@app.route('/posts/<int:id>')
def posts_detail(id):
    article = Article.query.get(id)
    return render_template('posts_detail.html', article=article)


@app.route('/posts/<int:id>/delete')
@login_required
def post_delete(id):
    article = Article.query.get_or_404(id)
    id = current_user.id
    if id == article.poster.id:
        try:
            db.session.delete(article)
            db.session.commit()
            flash('Post Deleted Successfully!')
            return redirect(url_for('posts'))
        except:
            return '<h1>При удалении статьи произошла ошибка</h1>'
    else:
        flash("Your Don't Have Permission To Delete This Post")
        return redirect(url_for('posts'))


@app.route('/posts/<int:id>/update', methods=['POST', 'GET'])
@login_required
def post_update(id):
    article = Article.query.get_or_404(id)
    form = PostForm()

    if form.validate_on_submit():
        article.title = form.title.data
        article.intro = form.intro.data
        article.slug = form.slug.data
        article.text = form.text.data

        db.session.add(article)
        db.session.commit()
        flash('Post Has Been Updated!')
        return redirect(url_for('posts_detail', id=article.id))

    elif current_user.id == article.poster_id:
        form.title.data = article.title
        form.intro.data = article.intro
        form.slug.data = article.slug
        form.text.data = article.text
        return render_template('post_update.html', article=article, form=form)
    else:
        flash("You Don't Have Permission To Update This Post!")
        articles = Article.query.order_by(Article.date)
        return render_template('posts.html')


@app.route('/add_post', methods=['POST', 'GET'])
@login_required
def add_post():
    form = PostForm()
    if form.validate_on_submit():
        poster = current_user.id
        article = Article(poster_id=poster, title=form.title.data, intro=form.intro.data, text=form.text.data,
                          slug=form.slug.data)
        try:
            db.session.add(article)
            db.session.commit()
            flash('Post Created Successfully!')
            return redirect('/posts')
        except:
            flash('Something went wrong...try again!')
            return render_template('add_post.html', article=article, form=form)

    else:
        return render_template('add_post.html', form=form)


@app.errorhandler(404)
def page_not_fount(e):
    return render_template('404.html')


if __name__ == '__main__':
    app.run(debug=True)




