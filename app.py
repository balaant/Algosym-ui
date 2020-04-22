from flask import Flask, redirect, flash, render_template, request, session, jsonify
from filtr_scripts import login_filter, password_filter
from database_connection import cursor, con
import os
import hashlib
import subprocess
from flasgger import Swagger
from urllib.parse import unquote

app = Flask(__name__)
Swagger(app)
app.static_url_path = '/static'
app.secret_key = 'motherhackers'
app.debug = True
app.config['STORMPATH_REGISTRATION_TEMPLATE'] = 'reg.html'
app.config['STORMPATH_LOGIN_TEMPLATE'] = 'login.html'


parent_dir = r"C:\work\best_hack2020\users_files"
bin_parent_dir = r"C:\work\best_hack2020\users_files_bin"
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'java'}




@app.route('/static/<string:filename>')
def user_api(filename):
    """
    User API
    This resource returns some information about files
    ---
    tags:
      - files
    parameters:
      - name: filename
        in: path
        type: string
        required: true
    responses:
      200:
        description: A single file item
        schema:
          id: user_response
          properties:
            username:
              type: string
              description: The filename
              default: some_filename

    """
    return jsonify({'filename': filename})


@app.route('/')
@app.route('/index')
def hello_world():
    """
            description: Index
    """
    return redirect('/login', code=302)


@app.route('/register', methods=['GET', 'POST'])
def register_page():


        if request.method == "POST":

            log = already_exist(login_filter(request.form.get("login")))
            password = password_filter(request.form.get("password"))
            copypassword = request.form.get("copypassword")

            if log is not None:
                if password == copypassword and password is not None:
                    cursor.execute(
                        """
                        INSERT INTO bhacklogins (login, password) VALUES ('{}', '{}')
                        """.format(str(log), str(password))
                    )
                    con.commit()
                    return redirect("/login")
                else:
                    flash("Password does not match!", "danger")
                    return render_template("reg.html")

        return render_template("reg.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if len(session.items()) > 1:
        return redirect("/mainPage")
    else:
        if request.method == "POST":
            log = login_filter(request.form.get("login"))
            password = password_filter(request.form.get("password"))

            login_inf = cursor.execute("""
            SELECT password FROM bhacklogins WHERE password = '{}' and login = '{}'
            """.format(password, log))
            login_inf = cursor.fetchall()

            # print(login_inf)

            if len(login_inf) == 0:
                return render_template("login.html")
            else:
                session["authenticated"] = True
                session["login"] = log
                return redirect("/mainPage")

        return render_template("login.html")


@app.route("/mainPage", methods=['GET', 'POST'])
def main_page():
    cursor.execute("""
            SELECT permit FROM bhacklogins WHERE login = '{}'
            """.format(session['login']))
    inf = cursor.fetchall()[0]
    print(inf)
    if 'user' in inf:
        if session.get("authenticated", None) is not None and session.get("authenticated", None) is not False:
            # print(session.get("authenticated", None))

            if 'visits' not in session:
                session['visits'] = 0

            md5_login = hashlib.md5(b"%b" % bytes(session['login'], "utf-8")).hexdigest()
            readed_bytes = ""
            alg_name = None
            check_for_exist(md5_login=md5_login)

            if request.query_string.decode():
                alg_name = str(request.query_string.decode()).split("=")[1]
                # print(alg_name)

            if request.method == "POST":
                cursor.execute("""
                    SELECT create_new_files FROM bhacklogins
                    """)
                inf = cursor.fetchone()
                if 0 in inf:
                    if "logoutAlg" in request.form:
                        session.clear()
                        return redirect("/")
                    else:
                        return redirect("/mainPage")
                elif 1 in inf:
                    if "saveAlg" in request.form:
                        get_info = request.form.get("code_area_blog")
                        # print(request.form.get("alg_name_top"))
                        # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                        save_file(path=parent_dir + f"\\{md5_login}\\{str(request.form.get('alg_name_top')).replace(' ', '')}")
                        return redirect(f"/mainPage?{request.query_string.decode()}")
                    elif "deleteAlg" in request.form:
                        del_alg(md5_login=md5_login, file=alg_name)
                        session.update()
                        return redirect("/mainPage")
                    elif "new_one" in request.form:
                        session['visits'] = session.get('visits') + 1
                        check_for_exist(md5_login=md5_login)
                        create_file(session['visits'], path = os.path.join(parent_dir, md5_login))
                    elif "logoutAlg" in request.form:
                        session.clear()
                        return redirect("/")
                    elif "compile_code" in request.form:
                        save_bin_file_to_user_bin_dir(md5login=md5_login, filename=alg_name)
                        compile_output = run_saved_bin_and_delete(md5_login)
                        if alg_name is not None:
                            readed_bytes = read_existed_file(path=parent_dir + f"\\{md5_login}\\{alg_name}")
                        return render_template("algorithm_template.html", ld=os.listdir(parent_dir + f"\\{md5_login}"),
                                               name=session['login'],
                                               get_name=alg_name,
                                               rb=readed_bytes,
                                               comp_outp=compile_output)

            elif request.method == "GET":
                try:
                    if alg_name is not None:
                        if alg_name in request.query_string.decode():
                            readed_bytes = read_existed_file(path=parent_dir + f"\\{md5_login}\\{alg_name}")
                except Exception:
                    return redirect("/mainPage")

            return render_template("algorithm_template.html", ld=os.listdir(parent_dir + f"\\{md5_login}"),
                                   name=session['login'],
                                   get_name=alg_name,
                                   rb=readed_bytes)
        else:
            return redirect("/login")

    elif "admin" in inf:
        cursor.execute("""
                        SELECT reg_new_one,create_new_files FROM bhacklogins where login = '{}'
                        """.format(session['login']))
        new_inf = cursor.fetchall()

        if request.method == "POST":
            if "new_reg" in request.form:
                if new_inf[0][0] == 0:
                    cursor.execute("""
                    UPDATE bhacklogins set reg_new_one = 1
                    """)
                    con.commit()
                elif new_inf[0][0] == 1:
                    cursor.execute("""
                    UPDATE bhacklogins set reg_new_one = 0
                    """)
                    con.commit()

            elif "change_stored" in request.form:
                if new_inf[0][1] == 0:
                    cursor.execute("""
                    UPDATE bhacklogins set create_new_files = 1
                    """)
                    con.commit()
                elif new_inf[0][1] == 1:
                    cursor.execute("""
                    UPDATE bhacklogins set create_new_files = 0
                    """)
                    con.commit()

        cursor.execute("""
            SELECT reg_new_one,create_new_files FROM bhacklogins where login = '{}'
            """.format(session['login']))
        new_inf = cursor.fetchall()
        return render_template("registration_template.html", md = new_inf[0][0], upd = new_inf[0][1])


@app.route("/logout")
def login_out():
    session.clear()
    return redirect("/")


@app.route("/mainPage/storage", methods= ['GET', 'POST'])
def store_settings():
    cursor.execute("""
                SELECT permit FROM bhacklogins WHERE login = '{}'
                """.format(session['login']))
    inf = cursor.fetchall()[0]
    print(inf)
    if 'user' in inf:
        return redirect("/mainPage")
    elif 'admin' in inf:
        cursor.execute("""
        SELECT login FROM bhacklogins
        """)
        get_all_logins = cursor.fetchall()
        for items in range(len(get_all_logins)):
            get_all_logins[items] = str(get_all_logins[items]).replace("(","").replace(")","").replace("'","").replace(",","")

        if request.method == "GET":
            try:
                md5_login = hashlib.md5(b"%b" % bytes(unquote(str(request.query_string.decode()).split("=")[1]), "utf-8")).hexdigest()
                if unquote(str(request.query_string.decode()).split("=")[1]) in get_all_logins:
                    global md5_login_user
                    md5_login_user = hashlib.md5(b"%b" % bytes(unquote(str(request.query_string.decode()).split("=")[1]), "utf-8")).hexdigest()
                    check_for_exist(md5_login=md5_login_user)
                    return render_template("admin_storage_template.html", render_login=get_all_logins,
                                           ld=os.listdir(parent_dir + f"\\{md5_login}"))
                else:
                    print(unquote(str(request.query_string.decode()).split("=")[1]))
                    rf = read_existed_file(path=parent_dir + f"\\{md5_login_user}" + f"\\{unquote(str(request.query_string.decode()).split('=')[1])}")
                    return render_template("admin_storage_template.html", render_login=get_all_logins,
                                                   ld=os.listdir(parent_dir + f"\\{md5_login_user}"),
                                                   read_file=rf,
                                                    fname = unquote(str(request.query_string.decode()).split("=")[1]))
            except Exception:
                return redirect(f"/mainPage/storage?{get_all_logins[0]}={get_all_logins[0]}")
        elif request.method == "POST":
            if "del_storage" in request.form:
                try:
                    del_alg(md5_login=md5_login_user, file= unquote(str(request.query_string.decode()).split("=")[1]))
                    return render_template("admin_storage_template.html", render_login=get_all_logins,
                                           ld=os.listdir(parent_dir + f"\\{md5_login_user}"))
                except Exception:
                    pass
        return render_template("admin_storage_template.html", render_login = get_all_logins)


def already_exist(login):
    user_info = cursor.execute("""
        SELECT login FROM bhacklogins where login = '{}'
        """.format(login))
    user_info = cursor.fetchall()
    print(user_info)

    if len(user_info) != 0:
        flash("Username already exist@", "danger")
        return None
    else:
        return login


def check_for_exist(md5_login):
    path = os.path.join(parent_dir, md5_login)

    if os.path.exists(path):
        pass
    else:
        os.mkdir(path)


def create_file(name_number, path):
    if f"Algorithm{str(name_number)}.java" not in os.listdir(path):
        with open(os.path.join(path, f"Algorithm{str(name_number)}.java"), "w"):
            pass
    else:
        print("already")


def del_alg(md5_login, file):
    path = os.path.join(parent_dir, md5_login, file)
    os.remove(path)


def read_existed_file(path):
    try:
        with open(path) as file:
            readed_bytes = file.read().replace('\n','')
            print(readed_bytes)
        return readed_bytes
    except Exception:
        raise


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def save_file(path):
    get_info = request.form.get("code_area_blog")
    with open(path, "w") as file:
        file.write(get_info)


def save_bin_file_to_user_bin_dir(md5login, filename):
    try:
        bin_path = bin_parent_dir + f"\\{md5login}"
        filepath = parent_dir + f"\\{md5login}" + f"\\{filename}"
        subprocess.call(f"javac -d {bin_path} {filepath}", shell=True)
    except Exception:
        pass


def run_saved_bin_and_delete(md5login):
    try:
        filename = os.listdir(bin_parent_dir + f"\\{md5login}")[0]
        stated_path = bin_parent_dir + f"\\{md5login}"
        os.chdir(stated_path)
        scal = subprocess.check_output(f"java {str(filename).replace('.class', '')}", shell=True)
        os.remove(stated_path + f"\\{filename}")
        return scal.decode()
    except Exception:
        return "[-] Error!"


