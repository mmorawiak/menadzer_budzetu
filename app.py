from flask import Flask, render_template, redirect, url_for, request, flash, Response
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, FloatField, SelectField, SubmitField
from wtforms.validators import InputRequired, Length, EqualTo
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_paginate import Pagination, get_page_parameter
from datetime import datetime, timezone
import csv
import io
import os

# Tworzenie aplikacji Flask
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

# Modele bazy danych
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    type = db.Column(db.String(50), nullable=False)  # "Income" lub "Expense"
    category = db.Column(db.String(100), nullable=True)  # Kategoria wydatku
    date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Formularze
class TransactionForm(FlaskForm):
    title = StringField(validators=[InputRequired()], render_kw={"placeholder": "Tytuł"})
    amount = FloatField(validators=[InputRequired()], render_kw={"placeholder": "Kwota"})
    type = SelectField(choices=[("Income", "Dochód"), ("Expense", "Wydatek")], validators=[InputRequired()])
    category = SelectField(choices=[
        ("Food", "Jedzenie"),
        ("Transport", "Transport"),
        ("Housing", "Mieszkanie"),
        ("Entertainment", "Rozrywka"),
        ("Other", "Inne")
    ], render_kw={"placeholder": "Kategoria"}, validators=[InputRequired()])
    submit = SubmitField("Zapisz")

class FilterForm(FlaskForm):
    type = SelectField(choices=[("", "Wszystkie"), ("Income", "Dochód"), ("Expense", "Wydatek")])
    submit = SubmitField("Filtruj")

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=150)], render_kw={"placeholder": "Username"})
    password = StringField(validators=[InputRequired()], render_kw={"placeholder": "Password"})
    confirm_password = StringField(validators=[InputRequired(), EqualTo('password')], render_kw={"placeholder": "Confirm Password"})
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=150)], render_kw={"placeholder": "Username"})
    password = StringField(validators=[InputRequired()], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")

# Funkcje pomocnicze
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def calculate_totals(transactions):
    total_income = sum(t.amount for t in transactions if t.type == "Income")
    total_expense = sum(t.amount for t in transactions if t.type == "Expense")
    balance = total_income - total_expense
    return total_income, total_expense, balance

# Widok strony głównej z paginacją
@app.route('/', methods=['GET', 'POST'])
@login_required
def home():
    print("Widok home został uruchomiony.")  # Debugging: sprawdzenie, czy widok działa

    # Formularz filtrowania
    form = FilterForm()
    page = request.args.get(get_page_parameter(), type=int, default=1)

    # Zapytanie o transakcje dla aktualnego użytkownika
    transactions_query = Transaction.query.filter_by(user_id=current_user.id)
    print("Zapytanie transakcji utworzone.")  # Debugging

    # Filtrowanie transakcji według typu
    if form.validate_on_submit() and form.type.data:
        print(f"Filtrowanie według typu: {form.type.data}")  # Debugging
        transactions_query = transactions_query.filter_by(type=form.type.data)

    # Paginacja i pobranie wszystkich transakcji
    transactions = transactions_query.order_by(Transaction.date.desc()).paginate(page=page, per_page=5, error_out=False)
    all_transactions = transactions_query.all()

    print("Transakcje pobrane:", all_transactions)  # Debugging: wyświetlenie transakcji

    # Obliczenie dochodów, wydatków i salda
    total_income, total_expense, balance = calculate_totals(all_transactions)
    print(f"Dochód: {total_income}, Wydatki: {total_expense}, Saldo: {balance}")  # Debugging

    # Grupowanie wydatków według kategorii
    expenses_by_category = db.session.query(
        Transaction.category, db.func.sum(Transaction.amount)
    ).filter(
        Transaction.user_id == current_user.id,  # Użytkownik
        Transaction.type == "Expense"           # Tylko wydatki
    ).group_by(Transaction.category).all()

    # Tworzenie list kategorii i kwot
    categories = [row[0] for row in expenses_by_category if row[0] is not None]
    amounts = [row[1] for row in expenses_by_category if row[1] is not None]

    print("Renderowanie szablonu home:")
    print("Kategorie (categories):", categories)
    print("Kwoty (amounts):", amounts)


    # Renderowanie szablonu
    return render_template(
        'home.html',
        transactions=transactions.items,
        pagination=transactions,
        form=form,
        total_income=total_income,
        total_expense=total_expense,
        balance=balance,
        categories=categories,
        amounts=amounts
    )

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_transaction():
    form = TransactionForm()
    if form.validate_on_submit():
        new_transaction = Transaction(
            title=form.title.data,
            amount=form.amount.data,
            type=form.type.data,
            category=form.category.data if form.type.data == "Expense" else None,
            user_id=current_user.id
        )
        db.session.add(new_transaction)
        db.session.commit()
        flash("Transakcja została dodana!", "success")
        return redirect(url_for('home'))
    return render_template('add_transaction.html', form=form)

@app.route('/edit/<int:transaction_id>', methods=['GET', 'POST'])
@login_required
def edit_transaction(transaction_id):
    transaction = Transaction.query.get_or_404(transaction_id)
    if transaction.user_id != current_user.id:
        flash("Nie masz dostępu do tej transakcji!", "danger")
        return redirect(url_for('home'))
    form = TransactionForm(obj=transaction)
    if form.validate_on_submit():
        transaction.title = form.title.data
        transaction.amount = form.amount.data
        transaction.type = form.type.data
        transaction.category = form.category.data if form.type.data == "Expense" else None
        db.session.commit()
        flash("Transakcja została zaktualizowana!", "success")
        return redirect(url_for('home'))
    return render_template('edit_transaction.html', form=form, transaction=transaction)

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

@app.route('/export', methods=['GET'])
@login_required
def export_transactions():
    transactions = Transaction.query.filter_by(user_id=current_user.id).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Data", "Tytuł", "Kwota", "Typ"])
    for t in transactions:
        writer.writerow([t.date.strftime('%Y-%m-%d'), t.title, t.amount, t.type])
    output.seek(0)
    return Response(
        output,
        mimetype='text/csv',
        headers={"Content-Disposition": "attachment;filename=transactions.csv"}
    )

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

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash("Zalogowano pomyślnie!", "success")
            return redirect(url_for('home'))
        flash("Błąd logowania. Sprawdź dane i spróbuj ponownie.", "danger")
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Zostałeś wylogowany.", "info")
    return redirect(url_for('login'))

# Obsługa błędu 404
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# Obsługa błędu 500
@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# Tworzenie bazy danych przy pierwszym uruchomieniu
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
