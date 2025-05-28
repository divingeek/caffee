from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'votre_cle_secrete'  # Assurez-vous de définir une clé secrète

def init_db():
    conn = sqlite3.connect('coffee.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            password TEXT NOT NULL,
            coffee_court INTEGER DEFAULT 0,
            coffee_long INTEGER DEFAULT 0,
            role TEXT NOT NULL DEFAULT 'user'
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS prices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            coffee_court_price REAL DEFAULT 0.25,
            coffee_long_price REAL DEFAULT 1.5
        )
    ''')
    # Insérer les prix initiaux si la table est vide
    c.execute('SELECT * FROM prices')
    if not c.fetchone():
        c.execute('INSERT INTO prices (coffee_court_price, coffee_long_price) VALUES (0.2, 0.4)')
    conn.commit()
    conn.close()

@app.route('/')
def index():
    if 'user_id' in session:
        user_id = session['user_id']
        conn = sqlite3.connect('coffee.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()
        c.execute('SELECT coffee_court_price, coffee_long_price FROM prices')
        prices = c.fetchone()
        conn.close()
        
        total_court = user[3] * prices[0]
        total_long = user[4] * prices[1]
        total_amount = total_court + total_long
        
        # Formater le montant total avec deux décimales
        total_amount_str = "{:.2f}".format(total_amount)
        
        return render_template('dashboard.html', user=user, total_amount=total_amount_str, prices=prices)
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        password = generate_password_hash(request.form['password'])
        
        conn = sqlite3.connect('coffee.db')
        c = conn.cursor()
        
        # Vérifier si le nom d'utilisateur existe déjà
        c.execute('SELECT * FROM users WHERE name = ?', (name,))
        existing_user = c.fetchone()
        
        if existing_user:
            flash("Ce nom d'utilisateur est déjà pris. Veuillez en choisir un autre.")
            return redirect(url_for('register'))
        
        # Si le nom d'utilisateur est disponible, créer le nouvel utilisateur
        c.execute('INSERT INTO users (name, password) VALUES (?, ?)', (name, password))
        conn.commit()
        conn.close()
        
        flash('Inscription réussie ! Vous pouvez vous connecter.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        name = request.form['name']
        password = request.form['password']
        
        conn = sqlite3.connect('coffee.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE name = ?', (name,))
        user = c.fetchone()
        conn.close()
        
        if user is None:
            flash("L'utilisateur n'existe pas. Veuillez vérifier votre nom d'utilisateur.")
        elif not check_password_hash(user[2], password):
            flash("Le mot de passe est incorrect. Veuillez réessayer.")
        else:
            session['user_id'] = user[0]
            return redirect(url_for('index'))
        
    return render_template('login.html')

@app.route('/add_coffee/<string:coffee_type>')
def add_coffee(coffee_type):
    if 'user_id' in session:
        user_id = session['user_id']
        conn = sqlite3.connect('coffee.db')
        c = conn.cursor()
        if coffee_type == "court":
            c.execute('UPDATE users SET coffee_court = coffee_court + 1 WHERE id = ?', (user_id,))
        elif coffee_type == "long":
            c.execute('UPDATE users SET coffee_long = coffee_long + 1 WHERE id = ?', (user_id,))
        conn.commit()
        conn.close()
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/admin')
def admin_dashboard():
    if 'user_id' in session:
        user_id = session['user_id']
        conn = sqlite3.connect('coffee.db')
        c = conn.cursor()
        c.execute('SELECT role FROM users WHERE id = ?', (user_id,))
        role = c.fetchone()[0]
        if role == 'admin':
            # Assurez-vous de récupérer l'identifiant de l'utilisateur (id)
            c.execute('SELECT name, coffee_court, coffee_long, id FROM users')
            users = c.fetchall()
            conn.close()
            return render_template('admin_dashboard.html', users=users)
        conn.close()
    return redirect(url_for('login'))



@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' in session:
        admin_id = session['user_id']
        conn = sqlite3.connect('coffee.db')
        c = conn.cursor()
        c.execute('SELECT role FROM users WHERE id = ?', (admin_id,))
        role = c.fetchone()[0]
        
        if role == 'admin':
            c.execute('DELETE FROM users WHERE id = ?', (user_id,))
            conn.commit()
            flash('Utilisateur supprimé avec succès.')
        conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/update_prices', methods=['GET', 'POST'])
def update_prices():
    if 'user_id' in session:
        user_id = session['user_id']
        conn = sqlite3.connect('coffee.db')
        c = conn.cursor()
        c.execute('SELECT role FROM users WHERE id = ?', (user_id,))
        role = c.fetchone()[0]
        if role == 'admin':
            if request.method == 'POST':
                new_court_price = float(request.form['coffee_court_price'])
                new_long_price = float(request.form['coffee_long_price'])
                c.execute('UPDATE prices SET coffee_court_price = ?, coffee_long_price = ?', (new_court_price, new_long_price))
                conn.commit()
                flash('Les prix ont été mis à jour avec succès.')
                return redirect(url_for('admin_dashboard'))
            c.execute('SELECT coffee_court_price, coffee_long_price FROM prices')
            prices = c.fetchone()
            conn.close()
            return render_template('update_prices.html', prices=prices)
        conn.close()
    return redirect(url_for('login'))

@app.route('/reset_counter/<int:user_id>', methods=['POST'])
def reset_counter(user_id):
    if 'user_id' in session:
        admin_id = session['user_id']
        conn = sqlite3.connect('coffee.db')
        c = conn.cursor()
        c.execute('SELECT role FROM users WHERE id = ?', (admin_id,))
        role = c.fetchone()[0]
        
        if role == 'admin':
            c.execute('UPDATE users SET coffee_court = 0, coffee_long = 0 WHERE id = ?', (user_id,))
            conn.commit()
            flash('Compteur de café remis à zéro avec succès.')
        conn.close()
    return redirect(url_for('admin_dashboard'))

def create_admin():
    conn = sqlite3.connect('coffee.db')
    c = conn.cursor()
    # Vérifier si un administrateur existe déjà
    c.execute('SELECT * FROM users WHERE role = ?', ('admin',))
    admin = c.fetchone()
    
    if admin is None:
        # Créer un nouvel administrateur si aucun n'existe
        admin_password = generate_password_hash('admin_password')  # Remplacez par un mot de passe sécurisé
        c.execute('INSERT INTO users (name, password, role) VALUES (?, ?, ?)', ('admin', admin_password, 'admin'))
        conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
    create_admin()  # Appeler la fonction pour s'assurer que l'admin est créé
    app.run(debug=True)