import re
import passlib.hash as ps
from flask import Markup
from flask import (Flask, flash, g, redirect, render_template, request,
                   send_file, session, url_for)
import os
import psycopg2





app = Flask(__name__)

app.config.update(dict(
    SECRET_KEY='59^6=;#&XP"2Vakfr4',
    DATABASE=os.path.join(app.root_path, 'users'),
    SITE_NAME='converter'
))


UPLOAD_FOLDER = 'target/'
ALLOWED_EXTENSIONS = {'json'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

app.secret_key = '59^6=;#&XP"2Vakfr4'


class savedata(object):

    @staticmethod
    def passcomper(string_pass, hash_pass):
        return ps.sha256_crypt.verify(string_pass, hash_pass)

    @staticmethod
    def encrypthash(password):
        return ps.sha256_crypt.encrypt(password)

    @staticmethod
    def encryptlog(password, code):

        # cipher = AES.new(code, AES.MODE_ECB)
        # encoded = base64.b64encode(cipher.encrypt(password.rjust(32)))
        # return encoded.decode('UTF-8')
        return password

    @staticmethod
    def decryptlog(password, code):

        # cipher = AES.new(code, AES.MODE_ECB)
        # decoded = cipher.decrypt(base64.b64decode(password))
        # return decoded.decode('UTF-8')
        return password

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() \
        in ALLOWED_EXTENSIONS


def save_flle(name, file):
    if 'logged' in session and session['logged'] :
        connection = get_db()
        cursor = connection.cursor()
        cursor.execute(f"""INSERT INTO melodis ( name, id_user, melody ) VALUES ( '{name}', (SELECT id FROM users WHERE user_name = '{session["username"]}'), '{file}');""")
        connection.commit()
    


def show_files():
    if 'logged' in session and session['logged'] :
        connection = get_db()
        cursor = connection.cursor()
        cursor.execute(f"""SELECT name FROM melodis WHERE id_user = (SELECT id FROM users WHERE user_name = '{session["username"]}');""")
        kursor = cursor.fetchall()
        if kursor:
            return [x[0] for x in kursor]
        else:
            return []
        


def load_file(name):
       if 'logged' in session and session['logged'] :
        
        connection = get_db()
        cursor = connection.cursor()

        cursor.execute(f"""SELECT melody FROM melodis WHERE id_user = (SELECT id FROM users WHERE user_name = '{session["username"]}') and name = '{name}';""")
        kursor = cursor.fetchall()
        return kursor[0][0]

def get_db():
    connection = psycopg2.connect(user="jnqwggjyljzzpl",
                                    password="395b87521bbff501cc785b4f62844c28390fd470c6d28bf41c3db01c646b0d20",
                                    host="ec2-54-73-147-133.eu-west-1.compute.amazonaws.com",
                                    port="5432",
                                    database="d8jm364tnlanbh")
    return connection


# @app.teardown_appcontext
# def close_db(error):
#     if g.get('db'):
#         g.db.close()


def login_test():
    if 'logged' not in session:
        session['logged'] = False


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    return redirect(url_for('login'))


@app.route("/")
def strona():
    name = {}
    login_test()
    return render_template('strona.html', name=name)


@app.route('/login', methods=['GET', 'POST'])
def login():
    
    
    # if 'logged' in session:
    #     if session['logged']:
    #         print('no jes')
    #         return redirect(url_for('index'))
    error = ''
    session['read'] = False
    session['db'] = None

    if request.method == 'POST':
        login = request.form['user']
        password = request.form['password']

        #===========================================
        if login == 'root' and password == 'root':
           session['username'] = login
           session['logged'] = True
           return render_template('strona.html', error=error)
        #===========================================!

        enc_login = login

        connection = get_db()
        cursor = connection.cursor()

        cursor.execute(f"SELECT * FROM users WHERE user_name = '{enc_login}';")
        connection.commit()
        kursor = cursor.fetchall()
       

        if not kursor :
            error = 'wrong login'
            return render_template('login.html', error=error)

        if (savedata.passcomper(password, kursor[0][2])):
            session['username'] = login
            session['logged'] = True
            return redirect(url_for('strona'))
        else:
            error = 'wrong password'


    return render_template('login.html', error=error)

@app.route('/index', methods=['GET', 'POST'])
def index():
    
    
    if 'logged' in session and session['logged']:
        user = f"Witaj {session['username']}"
        files = show_files()
    else :
        user = 'Jesteś nie zalogowany'
        files = ["Musisz się zalogować"]
   
    flash_message="False"

    if not 'melody_content' in session:
        session['melody_content'] = ''

    
    try :
        if request.method == 'POST':
            if list(request.form.keys())[0] == 'melody':

                name = request.form['filename']
                file = request.form['melody']
                save_flle(name, file)
            elif  list(request.form.keys())[0] == 'melody_read':
                name = request.form['r_filename']
                flash_message = "True"
                session['melody_content'] = Markup(load_file(name))
            
            
            elif  list(request.form.keys())[0] == 'return':
                return redirect(url_for('strona'))
    except :
        pass
    return render_template('index.html', len = files, melody_content = session['melody_content'] , flash_message=flash_message, user=user )



@app.route('/reg', methods=['GET', 'POST'])
def reg():

    if request.method == 'POST':
        user_name = request.form['user']
        password = request.form['password']
        re_password = request.form['re_password']

        if user_name == '' or password == '' or re_password == '':
            flash('complete the required forms')
            return redirect(url_for('reg'))


        if password != re_password:
            flash('passwords are not the same')
            return redirect(url_for('reg'))

        password = savedata.encrypthash(password)

        
        connection = get_db()
        cursor = connection.cursor()

        cursor.execute(f"INSERT INTO users ( user_name, user_password ) VALUES ( '{user_name}', '{password}');")
        connection.commit()
        return redirect(url_for('strona'))
        # except:
        #     print('baza niedziała')

        # except sqlite3.IntegrityError:
        #     flash('such user already exists')
        #     return redirect(url_for('reg'))

    return render_template('reg.html')


@app.route('/admin', methods=['GET', 'POST'])
def admin():

    return render_template('admin.html')

# @app.route('/read_db_on_begin', methods=['GET', 'POST'])
# def read_db_on_begin():
#     if 'logged' not in session:
#         session['logged'] = False
#     if not session['logged']:
#         return redirect(url_for('login'))

#     db = get_db()
#     kursor = db.execute('SELECT * FROM users')
#     kursor = kursor.fetchall()
#     r_db = []
#     lis = []
#     for user in kursor:

#         lis.append(user['id'])
#         r_db.append(lis)
#         lis = []
#     session['db'] = r_db
#     session['read'] = True
#     return redirect(url_for('admin'))

@app.route('/create',  methods=['GET', 'POST'])
def create():
 
    user_name = request.form['new_user']
    password = request.form['new_password']
    re_password = request.form['re_password']
    rights = request.form['rights']

    if user_name == '' or password == '' or re_password == '':
        flash('complete the required forms')
        return redirect(url_for('admin'))

    if password != re_password:
        flash('passwords are not the same')
        return redirect(url_for('admin'))

    password = savedata.encrypthash(password)

    try:
        db = get_db()
        db.execute('INSERT INTO users VALUES (?,?,?,?);',
                    [None, user_name, password, rights])
        db.commit()
    except sqlite3.IntegrityError:
        flash('such user already exists')
        return redirect(url_for('admin'))

    return redirect(url_for('admin'))

@app.route('/read', methods=['GET', 'POST'])
def read():

    if session['Show_cliked']:
        session['Show_cliked'] = False
    else:
        session['Show_cliked'] = True

    return redirect(url_for('admin'))


@app.route('/update', methods=['GET', 'POST'])
def update():


    e_name = request.form['eduser']
    name = request.form['name_user']
    password = request.form['password_user']
    right = request.form['rights']
    if e_name == '':
        flash('give user name')
        return redirect(url_for('admin'))

    db = get_db()
    if name != '':
        db.execute(
            'UPDATE users SET user_name = ?  WHERE user_name = ?;',
            [name, e_name])
        db.commit()

    if password != '':
        db.execute('UPDATE users SET user_password = ?  WHERE user_name = ?;',
                    [password, e_name])
        db.commit()

    if right != '':
        db.execute('UPDATE users SET rights = ?  WHERE user_name = ?;',
                    [right, e_name])
        db.commit()
    return redirect(url_for('admin'))
    


@app.route('/delete', methods=['GET', 'POST'])
def delete():
  
    user = request.form['name_user']

    if user == '':
        flash('give user name')
        return redirect(url_for('admin'))
    db = get_db()
    db.execute('DELETE FROM users WHERE user_name = ?;', [user])
    db.commit()
    return redirect(url_for('admin'))
