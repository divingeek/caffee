from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'votre_cle_secrete'  # Assurez-vous de définir une clé secrète
databaseFile="coffee.db"

def init_db():
    conn = sqlite3.connect(databaseFile)
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
        CREATE TABLE IF NOT EXISTS coffee_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            coffee_type TEXT,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS totals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            total_coffee INTEGER DEFAULT 0,
            total_since_reset INTEGER DEFAULT 0
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS coffee_package (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            package_name TEXT,
            active INTEGER DEFAULT 0
        )
    ''')
    # Insérer un paquet initial si la table est vide
    c.execute('SELECT * FROM coffee_package')
    if not c.fetchone():
        c.execute('INSERT INTO coffee_package (package_name, active) VALUES ("Méo BIO Espresso",1)')
    # Insérer les totaux initiaux si la table est vide
    c.execute('SELECT * FROM totals')
    if not c.fetchone():
        c.execute('INSERT INTO totals (total_coffee, total_since_reset) VALUES (0, 0)')
    c.execute('''
        CREATE TABLE IF NOT EXISTS prices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            coffee_court_price REAL DEFAULT 1.0,
            coffee_long_price REAL DEFAULT 1.5
        )
    ''')
    # Insérer les prix initiaux si la table est vide
    c.execute('SELECT * FROM prices')
    if not c.fetchone():
        c.execute('INSERT INTO prices (coffee_court_price, coffee_long_price) VALUES (1.0, 1.5)')
    conn.commit()
    conn.close()

@app.route('/')
def index():
    if 'user_id' in session:
        user_id = session['user_id']
        conn = sqlite3.connect(databaseFile)
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()
        c.execute('SELECT coffee_court_price, coffee_long_price FROM prices')
        prices = c.fetchone()
        
        # Récupérer le nom du paquet de café actuel
        c.execute('SELECT package_name FROM coffee_package WHERE active = 1')
        package_name = c.fetchone()[0]
        
        # Calcul des totaux
        total_court = user[3] * prices[0]
        total_long = user[4] * prices[1]
        total_amount = "{:.2f}".format(total_court + total_long)
        
        # Récupérer les totaux globaux
        c.execute('SELECT total_coffee, total_since_reset FROM totals')
        totals = c.fetchone()
        
        if totals is None:
            totals = (0, 0)  # Valeurs par défaut si aucun total n'existe

        conn.close()

        return render_template('dashboard.html', user=user, total_amount=total_amount, 
                               total_coffee=totals[0], total_since_reset=totals[1], 
                               package_name=package_name)
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        password = generate_password_hash(request.form['password'])
        
        conn = sqlite3.connect(databaseFile)
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
        
        conn = sqlite3.connect(databaseFile)
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


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/admin')
def admin_dashboard():
    if 'user_id' in session:
        user_id = session['user_id']
        conn = sqlite3.connect(databaseFile)
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
        conn = sqlite3.connect(databaseFile)
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
        conn = sqlite3.connect(databaseFile)
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
        conn = sqlite3.connect(databaseFile)
        c = conn.cursor()
        c.execute('SELECT role FROM users WHERE id = ?', (admin_id,))
        role = c.fetchone()[0]
        
        c.execute('UPDATE users SET coffee_court = 0, coffee_long = 0 WHERE id = ?', (user_id,))
        conn.commit()
        flash('Compteur de café remis à zéro avec succès.')

    return redirect(url_for('admin_dashboard'))

@app.route('/add_coffee/<string:coffee_type>')
def add_coffee(coffee_type):
    if 'user_id' in session:
        user_id = session['user_id']
        conn = sqlite3.connect(databaseFile)
        c = conn.cursor()
        if coffee_type == "court":
            c.execute('UPDATE users SET coffee_court = coffee_court + 1 WHERE id = ?', (user_id,))
        elif coffee_type == "long":
            c.execute('UPDATE users SET coffee_long = coffee_long + 1 WHERE id = ?', (user_id,))
        
        # Enregistrer la consommation dans le log
        c.execute('INSERT INTO coffee_log (user_id, coffee_type) VALUES (?, ?)', (user_id, coffee_type))
        
        # Mettre à jour les totaux globaux
        c.execute('UPDATE totals SET total_coffee = total_coffee + 1, total_since_reset = total_since_reset + 1')
        conn.commit()
        conn.close()
    return redirect(url_for('index'))

@app.route('/reset_totals', methods=['POST'])
def reset_totals():
    if 'user_id' in session:
        user_id = session['user_id']
        conn = sqlite3.connect(databaseFile)
        c = conn.cursor()
        c.execute('SELECT role FROM users WHERE id = ?', (user_id,))
        role = c.fetchone()[0]
        c.execute('UPDATE totals SET total_since_reset = 0')
        conn.commit()
        flash('Les totaux depuis le dernier reset ont été remis à zéro.')
        conn.close()
    return redirect(url_for('login'))

@app.route('/update_package', methods=['GET', 'POST'])
def update_package():
    if 'user_id' in session:
        user_id = session['user_id']
        conn = sqlite3.connect(databaseFile)
        c = conn.cursor()
        c.execute('SELECT role FROM users WHERE id = ?', (user_id,))
        role = c.fetchone()[0]
        if role == 'admin':
            if request.method == 'POST':
                new_package_name = request.form['package_name']
                c.execute('UPDATE coffee_package SET package_name = ?', (new_package_name,))
                conn.commit()
                flash('Le nom du paquet de café a été mis à jour avec succès.')
                return redirect(url_for('admin_dashboard'))
            c.execute('SELECT package_name FROM coffee_package')
            package = c.fetchone()
            conn.close()
            return render_template('update_package.html', package=package)
        conn.close()
    return redirect(url_for('login'))

@app.route('/add_package', methods=['GET', 'POST'])
def add_package():
    if 'user_id' in session:
        user_id = session['user_id']
        conn = sqlite3.connect(databaseFile)
        c = conn.cursor()
        c.execute('SELECT role FROM users WHERE id = ?', (user_id,))
        role = c.fetchone()[0]
        if role == 'admin':
            if request.method == 'POST':
                new_package_name = request.form['package_name']
                # Remettre à zéro les totaux et définir le nouveau paquet comme actif
                c.execute('UPDATE coffee_package SET active = 0 WHERE active = 1')
                c.execute('INSERT INTO coffee_package (package_name, active) VALUES (?, 1)', (new_package_name,))
                c.execute('UPDATE totals SET total_since_reset = 0')
                conn.commit()
                flash('Le nouveau paquet de café a été ajouté et les totaux ont été remis à zéro.')
                return redirect(url_for('admin_dashboard'))
            c.execute('SELECT package_name FROM coffee_package WHERE active = 1')
            active_package = c.fetchone()
            conn.close()
            return render_template('add_package.html', active_package=active_package)
        conn.close()
    return redirect(url_for('login'))


def create_admin():
    conn = sqlite3.connect(databaseFile)
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
    app.run(debug=True,host='0.0.0.0',port=5000)