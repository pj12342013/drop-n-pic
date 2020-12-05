import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session, send_file
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from uuid import uuid4

from helpers import apology, login_required
from PIL import Image


# Configure application
app = Flask(__name__)


# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

#max size of file is 100mb(1024 * 1024 is 1 mb)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
#picfolder = os.path.join('static', 'data')
#picfolder = r'workspace\final_project\final_project\static'
picfolder = r'D:\cloud_storage_project\final_project\static'
app.config["UPLOAD_FOLDER"] = picfolder
Session(app)

ALLOWED_EXTENSIONS = {'raw', 'png', 'jpg', 'jpeg', 'gif', 'bmp'}

ALLOWED_EXTENSIONS_VIDEO = { 'mp4', 'avi', 'mov', 'flv', 'wmv' } 

app.config['UPLOAD_EXTENSIONS'] = ['raw', 'png', 'jpg', 'jpeg', 'gif', 'bmp', 'mp4', 'avi', 'mov', 'flv', 'wmv']

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///final.db")

@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    uploads = db.execute("SELECT * FROM upload_list WHERE user_id=:u AND type='image'", u=session['user_id'])
    return render_template("index.html", uploads=uploads)

@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    """Show Account Details"""
    if request.method == "POST":
        return render_template("change.html")
    else:
        return render_template("account.html")


@app.route("/video")
@login_required
def video(): 
    uploads = db.execute("SELECT * FROM upload_list WHERE user_id=:u AND type='video'", u=session['user_id'])
    return render_template("video.html", uploads=uploads)    

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload(): 
    return render_template("upload.html")

def allowed_image_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def allowed_video_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS_VIDEO

@app.route('/', methods = ['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        if f and allowed_image_file(f.filename):
                unique_filename = make_unique(secure_filename(f.filename))
                secure_filename(f.filename)
                f.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
                db.execute("INSERT INTO 'upload_list'('user_id', 'filename', 'type') VALUES(:u, :f, 'image')", u=session['user_id'], f=unique_filename)
                return render_template("index.html")
                                       
        elif f and allowed_video_file(f.filename): 
                try: 
                    unique_filename = make_unique(secure_filename(f.filename))
                    secure_filename(f.filename)
                    f.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
                    db.execute("INSERT INTO 'upload_list'('user_id', 'filename', 'type') VALUES(:u, :f, 'video')", u=session['user_id'], f=unique_filename)
                    return render_template("index.html")
                
                except FileNotFoundError: 
                    flash("No file found")
                    return render_template("upload.html")  
        
        if f.filename != '':
            file_ext = os.path.splitext(f.filename)[1]
            if file_ext not in app.config['UPLOAD_EXTENSIONS']:
                return "Invalid File", 400

        
        else:
            flash("Only image and video files allowed")
            return render_template("upload.html")         

@app.route("/pictures")
@login_required
def pictures():
    uploads = db.execute("SELECT * FROM upload_list WHERE user_id=:u AND type='image'", u=session['user_id'])
    return render_template("pictures.html", uploads=uploads)
        
@app.route('/return-files/<filename>')
def return_files_tut(filename):
    file_path = app.config['UPLOAD_FOLDER']+'\\' + filename
    return send_file(file_path, as_attachment=True, attachment_filename='')

@app.route('/delete-files/<filename>')
def delete_file(filename):
    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    db.execute("DELETE FROM upload_list WHERE filename=:filename AND user_id=:u_id", filename=filename, u_id=session['user_id'])
    uploads = db.execute("SELECT * FROM upload_list WHERE user_id=:u", u=session['user_id'])
    return render_template("pictures.html", uploads=uploads)

def make_unique(filename):
    ident = uuid4().__str__()[:8]
    return f"{ident}-{filename}"

@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    """change password"""

    if request.method == "POST":

        pass_hash = generate_password_hash(request.form.get("new password"))

        current_pass = db.execute("SELECT hash FROM users WHERE id = :u_id", u_id = session['user_id'])

        #if new password matches old password
        if check_password_hash(current_pass[0]['hash'], request.form.get("new password")):
            flash("New Password cannot be same as old password")
            return render_template("change.html")

        elif not check_password_hash(pass_hash, request.form.get("reconfirm password")):
            flash("Passwords do not match")
            return render_template("change.html")

        elif not request.form.get("new password")  or not request.form.get("reconfirm password"):
            flash("Password cannot be blank")
            return render_template("change.html")

        else:
            db.execute("UPDATE users SET hash=:passw WHERE id = :u_id", passw=pass_hash, u_id=session['user_id'])
            flash("password successfully changed")
            return redirect("/")

    else:
        return render_template("change.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            flash("Must Provide Username")
            return render_template("login.html")

        # Ensure password was submitted
        elif not request.form.get("password"):
            flash("Must Provide Password")
            return render_template("login.html")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            flash("Invalid Username/Password")
            return render_template("login.html")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")



@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        #generate password hash
        pass_hash = generate_password_hash(request.form.get("password"))

        check_user = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))
        #ensure username submitted
        if not request.form.get("username"):
            flash("Must Provide Username")
            return render_template("register.html")
            #return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            flash("Must Provide Password")
            return render_template("register.html")
            #return apology("must provide password", 403)

        #ensure passwords match
        elif request.form.get("password") != request.form.get("reconfirm password"):
            flash("passwords do not match")
            return render_template("register.html")
        #ensure unique username
        elif len(check_user) != 0:
            flash("Username already taken")
            return render_template("register.html")

        else:
            db.execute("INSERT INTO users(username, hash) VALUES(:username, :pass_hash)",
            username=request.form.get("username"), pass_hash=pass_hash)
            flash("Successly Registered, please log in")
            return render_template("login.html")
            # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)




