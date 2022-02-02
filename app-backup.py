
from flask import Flask, flash, render_template, url_for, request, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
from forms import UserForm, PasswordForm, PostForm, LoginForm
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, logout_user, current_user, login_required


app = Flask(__name__)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:password123@localhost/our_users'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'secret key'
db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200), nullable=False, unique=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    password_hash = db.Column(db.String(128))

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


class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    intro = db.Column(db.String(300), nullable=False)
    author = db.Column(db.String(255))
    slug = db.Column(db.String(255))
    text = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Article {self.id}>'


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
    return render_template('dashboard.html')


@app.route('/user/delete/<int:id>', methods=['POST', 'GET'])
def user_delete(id):
    form = UserForm()
    user_to_delete = Users.query.get_or_404(id)
    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash('User Deleted Successfully')
        users = Users.query.order_by(Users.date_added).all()
        return render_template('index.html', form=form, users=users)
    except:
        flash('Error! Something went wrong...try again')
        users = Users.query.order_by(Users.date_added).all()
        return render_template('index.html', form=form, users=users)


@app.route('/user/update/<int:id>', methods=['POST', 'GET'])
def user_update(id):
    form = UserForm()
    user_to_update = Users.query.get_or_404(id)
    if request.method == 'POST':
        user_to_update.name = request.form['name']
        user_to_update.email = request.form['email']
        user_to_update.username = request.form['username']
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
    return render_template('index.html')


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

    try:
        db.session.delete(article)
        db.session.commit()
        flash('Post Deleted Successfully!')
        return redirect('/posts')
    except:
        return '<h1>При удалении статьи произошла ошибка</h1>'


@app.route('/posts/<int:id>/update', methods=['POST', 'GET'])
@login_required
def post_update(id):
    article = Article.query.get_or_404(id)
    form = PostForm()
    if form.validate_on_submit():
        article.title = form.title.data
        article.intro = form.intro.data
        article.author = form.author.data
        article.slug = form.slug.data
        article.text = form.text.data

        db.session.add(article)
        db.session.commit()
        flash('Post Has Been Updated!')
        return redirect(url_for('posts_detail', id=article.id))

    form.title.data = article.title
    form.intro.data = article.intro
    form.author.data = article.author
    form.slug.data = article.slug
    form.text.data = article.text

    return render_template('post_update.html', article=article, form=form)


@app.route('/add_post', methods=['POST', 'GET'])
@login_required
def add_post():
    form = PostForm()
    if form.validate_on_submit():
        article = Article(title=form.title.data, intro=form.intro.data, text=form.text.data, slug=form.slug.data,
                          author=form.author.data)
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



