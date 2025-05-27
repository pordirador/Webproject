import os
from datetime import datetime, timedelta
from threading import Thread
import time
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask import (
    Flask, render_template, redirect, url_for, flash,
    request, abort, send_from_directory, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user,
    logout_user, login_required, current_user
)
from flask_wtf import FlaskForm
from wtforms import (
    StringField, PasswordField, SubmitField,
    TextAreaField, DateTimeLocalField, SelectField, FileField
)
from wtforms.validators import DataRequired, Length, Email, ValidationError

try:
    from win10toast import ToastNotifier

    toaster = ToastNotifier()
    WIN_NOTIFICATIONS = True
except ImportError:
    WIN_NOTIFICATIONS = False

# ==============================================
# ИНИЦИАЛИЗАЦИЯ ПРИЛОЖЕНИЯ
# ==============================================
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# ==============================================
# МОДЕЛИ БАЗЫ ДАННЫХ
# ==============================================
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    tasks = db.relationship('Task', backref='author', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Task(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    due_date = db.Column(db.DateTime)
    priority = db.Column(db.String(20), default='medium')
    is_completed = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    attachment = db.Column(db.String(200))
    notified = db.Column(db.Boolean, default=False)


# ==============================================
# ФОРМЫ
# ==============================================
class LoginForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')


class RegistrationForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired(), Length(min=4, max=50)])
    email = StringField('Email', validators=[DataRequired(), Length(max=100)])
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Подтвердите пароль', validators=[DataRequired()])
    submit = SubmitField('Зарегистрироваться')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Это имя пользователя уже занято')

    def validate_email(self, email):
        # Простая проверка формата email
        if '@' not in email.data or '.' not in email.data.split('@')[-1]:
            raise ValidationError('Некорректный email адрес')

        # Проверка уникальности
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Этот email уже используется')

    def validate_password(self, password):
        if password.data != self.confirm_password.data:
            raise ValidationError('Пароли не совпадают')


class TaskForm(FlaskForm):
    title = StringField('Название', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Описание')
    due_date = DateTimeLocalField('Срок выполнения', format='%Y-%m-%dT%H:%M', validators=[DataRequired()])
    priority = SelectField('Приоритет', choices=[
        ('low', 'Низкий'),
        ('medium', 'Средний'),
        ('high', 'Высокий')
    ], default='medium')
    attachment = FileField('Вложение')
    submit = SubmitField('Сохранить')


# ==============================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ==============================================
def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def save_uploaded_file(file):
    if not file or file.filename == '':
        return None

    if allowed_file(file.filename):
        filename = secure_filename(file.filename)
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return filepath
    return None


def check_tasks():
    with app.app_context():
        while True:
            now = datetime.now()
            due_soon = now + timedelta(minutes=5)

            # Получаем всех пользователей
            users = User.query.all()

            for user in users:
                tasks = Task.query.filter(
                    Task.due_date <= due_soon,
                    Task.user_id == user.id,
                    Task.is_completed == False,
                    Task.notified == False
                ).all()

                for task in tasks:
                    if WIN_NOTIFICATIONS:
                        toaster.show_toast(
                            "Напоминание о задаче",
                            f"Скоро срок: {task.title}\nДо дедлайна: {task.due_date.strftime('%d.%m.%Y %H:%M')}",
                            duration=10
                        )
                    task.notified = True
                    db.session.commit()

            time.sleep(60)


# ==============================================
# МАРШРУТЫ
# ==============================================
@app.route('/')
@login_required
def index():
    sort_by = request.args.get('sort', 'due_date')

    if sort_by == 'priority':
        tasks = Task.query.filter_by(user_id=current_user.id).order_by(
            db.case(
                {'high': 1, 'medium': 2, 'low': 3},
                value=Task.priority
            ),
            Task.due_date.asc()
        ).all()
    else:
        tasks = Task.query.filter_by(user_id=current_user.id).order_by(
            Task.due_date.asc()
        ).all()

    return render_template('index.html', tasks=tasks, sort_by=sort_by, now=datetime.now())
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        flash('Неверное имя пользователя или пароль', 'danger')
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegistrationForm()
    if form.validate_on_submit():
        if form.password.data != form.confirm_password.data:
            flash('Пароли не совпадают', 'danger')
            return redirect(url_for('register'))

        user = User(
            username=form.username.data,
            email=form.email.data
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Регистрация успешна! Теперь вы можете войти', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/task/new', methods=['GET', 'POST'])
@login_required
def new_task():
    form = TaskForm()
    if form.validate_on_submit():
        filepath = save_uploaded_file(form.attachment.data)
        task = Task(
            title=form.title.data,
            description=form.description.data,
            due_date=form.due_date.data,
            priority=form.priority.data,
            user_id=current_user.id,
            attachment=filepath
        )
        db.session.add(task)
        db.session.commit()
        flash('Задача создана!', 'success')
        return redirect(url_for('index'))
    return render_template('create_task.html', form=form)


@app.route('/task/<int:task_id>')
@login_required
def view_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        abort(403)
    return render_template('task.html', task=task, now=datetime.now())


@app.route('/task/<int:task_id>/update', methods=['GET', 'POST'])
@login_required
def update_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        abort(403)

    form = TaskForm()
    if form.validate_on_submit():
        task.title = form.title.data
        task.description = form.description.data
        task.due_date = form.due_date.data
        task.priority = form.priority.data
        task.notified = False  # Сбрасываем уведомление при изменении

        if form.attachment.data:
            if task.attachment and os.path.exists(task.attachment):
                os.remove(task.attachment)
            task.attachment = save_uploaded_file(form.attachment.data)

        db.session.commit()
        flash('Задача обновлена!', 'success')
        return redirect(url_for('view_task', task_id=task.id))
    elif request.method == 'GET':
        form.title.data = task.title
        form.description.data = task.description
        form.due_date.data = task.due_date
        form.priority.data = task.priority

    return render_template('update_task.html', form=form, task=task)


@app.route('/task/<int:task_id>/delete', methods=['POST'])
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        abort(403)

    if task.attachment and os.path.exists(task.attachment):
        os.remove(task.attachment)

    db.session.delete(task)
    db.session.commit()
    flash('Задача удалена!', 'success')
    return redirect(url_for('index'))


@app.route('/download/<int:task_id>')
@login_required
def download_attachment(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        abort(403)
    if not task.attachment:
        abort(404)
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        os.path.basename(task.attachment),
        as_attachment=True
    )


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, 'static'),
        'favicon.ico',
        mimetype='image/vnd.microsoft.icon'
    )


# ==============================================
# ЗАПУСК ПРИЛОЖЕНИЯ
# ==============================================
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # Создаем тестового пользователя
        if not User.query.first():
            admin = User(
                username='admin',
                email='admin@example.com',
                password_hash=generate_password_hash('admin')
            )
            db.session.add(admin)
            db.session.commit()

    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    # Запускаем проверку задач в фоне
    if WIN_NOTIFICATIONS:
        Thread(target=check_tasks, daemon=True).start()

    app.run(debug=True)