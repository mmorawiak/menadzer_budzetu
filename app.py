from flask import Flask, render_template, redirect, url_for, request, send_file, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, FloatField, SelectField, SubmitField
from wtforms.validators import InputRequired, Length, EqualTo
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
import csv
import os

# Tworzymy aplikację Flask
app = Flask(__name__)

# Konfiguracja aplikacji
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(app.instance_path, 'budget_manager.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'supersecretkey'

# Inicjalizacja narzędzi
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Tworzenie folderu instance, jeśli nie istnieje
if not os.path.exists(app.instance_path):
    os.makedirs(app.instance_path)

# Definicja tabeli User w bazie danych
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

# Definicja tabeli Transaction w bazie danych
class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    type = db.Column(db.String(50), nullable=False)  # "Income" lub "Expense"
    date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Formularz dodawania i edycji transakcji
class TransactionForm(FlaskForm):
    title = StringField(validators=[InputRequired()], render_kw={"placeholder": "Tytuł"})
    amount = FloatField(validators=[InputRequired()], render_kw={"placeholder": "Kwota"})
    type = SelectField(choices=[("Income", "Dochód"), ("Expense", "Wydatek")], validators=[InputRequired()])
    submit = SubmitField("Zapisz")

# Formularz filtrowania transakcji
class FilterForm(FlaskForm):
    type = SelectField(choices=[("", "Wszystkie"), ("Income", "Dochód"), ("Expense", "Wydatek")])
    submit = SubmitField("Filtruj")

# Formularz rejestracji
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=150)], render_kw={"placeholder": "Username"})
    password = StringField(validators=[InputRequired()], render_kw={"placeholder": "Password"})
    confirm_password = StringField(validators=[InputRequired(), EqualTo('password')], render_kw={"placeholder": "Confirm Password"})
    submit = SubmitField("Register")

# Formularz logowania
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=150)], render_kw={"placeholder": "Username"})
    password = StringField(validators=[InputRequired()], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")

# Konfiguracja menadżera logowania
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Strona główna z filtrowaniem i podsumowaniem
@app.route('/', methods=['GET', 'POST'])
@login_required
def home():
    form = FilterForm()
    transactions = Transaction.query.filter_by(user_id=current_user.id)

    # Filtrowanie transakcji
    if form.validate_on_submit() and form.type.data:
        transactions = transactions.filter_by(type=form.type.data)

    transactions = transactions.order_by(Transaction.date.desc()).all()

    # Podsumowanie
    total_income = sum(t.amount for t in transactions if t.type == "Income")
    total_expense = sum(t.amount for t in transactions if t.type == "Expense")
    balance = total_income - total_expense

    return render_template('home.html', transactions=transactions, form=form, 
                           total_income=total_income, total_expense=total_expense, balance=balance)

# Widok dodawania transakcji
@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_transaction():
    form = TransactionForm()
    if form.validate_on_submit():
        new_transaction = Transaction(
            title=form.title.data,
            amount=form.amount.data,
            type=form.type.data,
            user_id=current_user.id
        )
        db.session.add(new_transaction)
        db.session.commit()
        flash("Transakcja została dodana!", "success")
        return redirect(url_for('home'))
    return render_template('add_transaction.html', form=form)

# Widok edycji transakcji
@app.route('/edit/<int:transaction_id>', methods=['GET', 'POST'])
@login_required
def edit_transaction(transaction_id):
    # Pobierz transakcję z bazy danych
    transaction = Transaction.query.get_or_404(transaction_id)
    
    # Upewnij się, że użytkownik jest właścicielem transakcji
    if transaction.user_id != current_user.id:
        flash("Nie masz dostępu do tej transakcji!", "danger")
        return redirect(url_for('home'))
    
    # Wypełnienie formularza danymi transakcji
    form = TransactionForm(obj=transaction)

    if form.validate_on_submit():
        # Zaktualizowanie danych transakcji
        transaction.title = form.title.data
        transaction.amount = form.amount.data
        transaction.type = form.type.data
        
        # Zapisanie zmian do bazy danych
        db.session.commit()
        
        # Powrót na stronę główną po zapisaniu zmian
        flash("Transakcja została zaktualizowana!", "success")
        return redirect(url_for('home'))
    
    # Renderowanie formularza z danymi transakcji
    return render_template('edit_transaction.html', form=form, transaction=transaction)

# Widok usuwania transakcji
@app.route('/delete/<int:transaction_id>', methods=['POST'])
@login_required
def delete_transaction(transaction_id):
    transaction = Transaction.query.get_or_404(transaction_id)
    if transaction.user_id != current_user.id:
        return redirect(url_for('home'))
    db.session.delete(transaction)
    db.session.commit()
    flash("Transakcja została usunięta!", "success")
    return redirect(url_for('home'))

# Eksport transakcji do CSV
@app.route('/export', methods=['GET'])
@login_required
def export_transactions():
    transactions = Transaction.query.filter_by(user_id=current_user.id).all()
    filepath = f"{current_user.username}_transactions.csv"

    # Tworzenie pliku CSV
    with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Data", "Tytuł", "Kwota", "Typ"])
        for t in transactions:
            writer.writerow([t.date.strftime('%Y-%m-%d'), t.title, t.amount, t.type])

    return send_file(filepath, as_attachment=True)

# Widok rejestracji
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("Rejestracja zakończona sukcesem!", "success")
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# Widok logowania
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash("Zalogowano pomyślnie!", "success")
            return redirect(url_for('home'))
        else:
            flash("Błąd logowania. Sprawdź dane i spróbuj ponownie.", "danger")
    return render_template('login.html', form=form)

# Widok wylogowania
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Zostałeś wylogowany.", "info")
    return redirect(url_for('login'))

# Tworzenie bazy danych przy pierwszym uruchomieniu
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Tworzy tabele w bazie danych
    app.run(debug=True)
