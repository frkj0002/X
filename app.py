from flask import Flask, render_template, request, session, redirect, url_for, jsonify
from flask_session import Session
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename
import gspread
import requests
import json
import time
import uuid
import os
import x 
import dictionary
import io
import csv

from oauth2client.service_account import ServiceAccountCredentials

from icecream import ic
ic.configureOutput(prefix=f'----- | ', includeContext=True)

app = Flask(__name__)

# Set the maximum file size to 10 MB
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024   # 1 MB

app.config['SESSION_TYPE'] = 'filesystem'
Session(app)
 
##############################
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_FOLDER = 'static/images/user_avatars'
UPLOAD_POST_FOLDER = 'static/images/post_images'

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

##############################
##############################
##############################
def _____USER_____(): pass 
##############################
##############################
##############################

@app.get("/")
def view_index():
   
    return render_template("index.html")

##############################
@app.context_processor
def global_variables():
    return dict (
        dictionary = dictionary,
        x = x
    )


##############################
@app.route("/login", methods=["GET", "POST"])
@app.route("/login/<lan>", methods=["GET", "POST"])
@x.no_cache
def login(lan = "english"):

    if lan not in x.allowed_languages: lan = "english"
    x.default_language = lan

    if request.method == "GET":
        if session.get("user", ""): return redirect(url_for("home"))
        return render_template("login.html", lan=lan)

    if request.method == "POST":
        try:
            # Validate           
            user_email = x.validate_user_email(lan)
            user_password = x.validate_user_password(lan)
            # Connect to the database
            q = "SELECT * FROM users WHERE user_email = %s"
            db, cursor = x.db()
            cursor.execute(q, (user_email,))
            user = cursor.fetchone()
            if not user: 
                toast_error = render_template("___toast_error.html", message="user not found")
                return f"<mixhtml mix-bottom='#toast'>{toast_error}</mixhtml>"

            if not check_password_hash(user["user_password"], user_password):
                raise Exception(dictionary.invalid_credentials[lan], 400)

            if user["user_verification_key"] != "":
                raise Exception(dictionary.user_not_verified[lan], 400)

            user.pop("user_password")
            session["user"] = user

            if user.get("user_role") == "admin":
                return f"""<browser mix-redirect="/home-admin"></browser>"""
            else:
                return f"""<browser mix-redirect="/home"></browser>"""

        except Exception as ex:
            ic(ex)

            # User errors
            if ex.args[1] == 400:
                toast_error = render_template("___toast_error.html", message=ex.args[0])
                return f"""<browser mix-update="#toast">{ toast_error }</browser>""", 400

            # System or developer error
            toast_error = render_template("___toast_error.html", message="System under maintenance")
            return f"""<browser mix-bottom="#toast">{ toast_error }</browser>""", 500

        finally:
            if "cursor" in locals(): cursor.close()
            if "db" in locals(): db.close()




##############################
@app.route("/signup", methods=["GET", "POST"])
@app.route("/signup/<lan>", methods=["GET", "POST"])
def signup(lan = "english"):

    if lan not in x.allowed_languages: lan = "english"
    x.default_language = lan

    if request.method == "GET":
        return render_template("signup.html", lan=lan)

    if request.method == "POST":
        try:
            # Validate
            user_email = x.validate_user_email()
            user_password = x.validate_user_password()
            user_username = x.validate_user_username()
            user_first_name = x.validate_user_first_name()

            user_pk = uuid.uuid4().hex
            user_role = "user"
            user_blocked = 0
            user_hashed_password = generate_password_hash(user_password)
            user_reset_password_key = 0
            user_last_name = ""
            user_avatar_path = ""
            user_verification_key = uuid.uuid4().hex
            user_verified_at = 0
            user_total_followers = 0
            user_total_following = 0
            user_created_at = int(time.time())
            user_updated_at = 0


            # Connect to the database
            q = "INSERT INTO users VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            db, cursor = x.db()
            cursor.execute(q, (user_pk, user_role, user_blocked, user_email, user_hashed_password, user_reset_password_key, user_username, 
            user_first_name, user_last_name, user_avatar_path, user_verification_key, user_verified_at, user_total_followers, user_total_following, user_created_at, user_updated_at))
            db.commit()

            # send verification email
            email_verify_account = render_template("_email_verify_account.html", user_verification_key=user_verification_key)
            ic(email_verify_account)
            x.send_email(user_email, "Verify your account", email_verify_account)

            verification_modal = render_template("_verification_modal.html")
            return f"""<mixhtml mix-update="#modal">{verification_modal}</mixhtml>""", 200

        except Exception as ex:
            ic(ex)
            # User errors
            if ex.args[1] == 400:
                toast_error = render_template("___toast_error.html", message=ex.args[0])
                return f"""<mixhtml mix-update="#toast">{ toast_error }</mixhtml>""", 400
            
            # Database errors
            if "Duplicate entry" and user_email in str(ex): 
                toast_error = render_template("___toast_error.html", message="Email already registered")
                return f"""<mixhtml mix-update="#toast">{ toast_error }</mixhtml>""", 400
            if "Duplicate entry" and user_username in str(ex): 
                toast_error = render_template("___toast_error.html", message="Username already registered")
                return f"""<mixhtml mix-update="#toast">{ toast_error }</mixhtml>""", 400
            
            # System or developer error
            toast_error = render_template("___toast_error.html", message="System under maintenance")
            return f"""<mixhtml mix-bottom="#toast">{ toast_error }</mixhtml>""", 500

        finally:
            if "cursor" in locals(): cursor.close()
            if "db" in locals(): db.close()



##############################
@app.get("/home")
@x.no_cache
def home():
    try:
        user = session.get("user", "")
        if not user:
            return redirect(url_for("login"))

        db, cursor = x.db()

        # Hent posts inkl. om brugeren har liket og post_total_likes fra kolonnen i posts
        q = """
        SELECT
        posts.*,
        users.*,
        posts.post_total_likes,
        EXISTS(
            SELECT 1
            FROM likes
            WHERE post_fk = posts.post_pk
            AND user_fk = %s
        ) AS user_liked
        FROM posts
        JOIN users ON users.user_pk = posts.post_user_fk
        WHERE posts.post_deleted_at = 0
        ORDER BY posts.post_created_at DESC
        LIMIT 5
        """
        cursor.execute(q, (user["user_pk"],))
        tweets = cursor.fetchall()

        # Hent trends
        q = "SELECT * FROM trends ORDER BY RAND() LIMIT 3"
        cursor.execute(q)
        trends = cursor.fetchall()

        # Hent forslag til brugere
        q = "SELECT * FROM users WHERE user_pk != %s ORDER BY RAND() LIMIT 3"
        cursor.execute(q, (user["user_pk"],))
        suggestions = cursor.fetchall()

        return render_template(
            "home.html",
            tweets=tweets,
            trends=trends,
            suggestions=suggestions,
            user=user
        )
    
    except Exception as ex:
        ic(ex)
        return "error"
    
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()

##############################
@app.get("/home-admin")
def home_admin():
    try:
        admin = session.get("user")
        if not admin or admin.get("user_role", "").lower() != "admin":
            return '<browser mix-redirect="/home"></browser>'

        db, cursor = x.db()

        # Antal brugere
        q = "SELECT COUNT(*) AS count FROM users WHERE user_role='user'"
        cursor.execute(q)
        total_users = cursor.fetchone()['count']

        # Antal posts
        q = "SELECT COUNT(*) AS count FROM posts"
        cursor.execute(q)
        total_posts = cursor.fetchone()['count']

        # Antal blokerede brugere
        q = "SELECT COUNT(*) AS count FROM users WHERE user_blocked='1'"
        cursor.execute(q)
        blocked_users = cursor.fetchone()['count']

        # Antal blokerede posts
        q = "SELECT COUNT(*) AS count FROM posts WHERE post_blocked='1'"
        cursor.execute(q)
        blocked_posts = cursor.fetchone()['count']

        return render_template("home_admin.html",
                               user=admin,
                               total_users=total_users,
                               total_posts=total_posts,
                               blocked_users=blocked_users,
                               blocked_posts=blocked_posts)
    
    except Exception as ex:
        ic(ex)
        return "error"
    
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()
    

##############################
@app.route("/verify-account", methods=["GET"])
def verify_account():
    try:
        user_verification_key = x.validate_uuid4_without_dashes(request.args.get("key", ""))
        user_verified_at = int(time.time())
        db, cursor = x.db()
        q = "UPDATE users SET user_verification_key = '', user_verified_at = %s WHERE user_verification_key = %s"
        cursor.execute(q, (user_verified_at, user_verification_key))
        db.commit()
        if cursor.rowcount != 1: raise Exception("Invalid key", 400)
        return redirect( url_for('login') )
    except Exception as ex:
        ic(ex)
        if "db" in locals(): db.rollback()
        # User errors
        if ex.args[1] == 400: return ex.args[0], 400    

        # System or developer error
        return "Cannot verify user"

    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()
    

##############################
@app.route("/forgot-password", methods=["GET", "POST"])
def view_forgot_form():
    if request.method == "GET":
        return render_template("_forgot_password.html")
    
    if request.method == "POST":
        user_email = request.form.get("user_email", "").strip()

        try:
            db, cursor = x.db()
            # find brugeren i databasen
            q = "SELECT user_pk FROM users WHERE user_email = %s"
            cursor.execute(q, (user_email,))
            user = cursor.fetchone()

            if user:
                user_pk = user["user_pk"]
                ic(user)
                reset_key = uuid.uuid4().hex
                q = "UPDATE users SET user_reset_password_key = %s WHERE user_pk = %s"
                cursor.execute(q, (reset_key, user_pk))
                db.commit()

                # Send reset password email
                email_forgot_password = render_template("_email_forgot_password.html", reset_key=reset_key)
                ic(email_forgot_password)
                x.send_email(user_email, "Reset your password", email_forgot_password)

                return redirect(url_for("login"))

        except Exception as ex:
            ic(ex)
            if "db" in locals(): db.rollback()
            # User errors
            if ex.args[1] == 400: return ex.args[0], 400    

            # System or developer error
            return "Cannot send link to user"

        finally:
            if "cursor" in locals(): cursor.close()
            if "db" in locals(): db.close()
     
##############################
@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if request.method == "GET":
        try:
            reset_key = request.args.get("key", "").strip()
            db, cursor = x.db()
            q = "SELECT user_pk FROM users WHERE user_reset_password_key = %s"
            cursor.execute(q, (reset_key,))
            user = cursor.fetchone()

            if not user: 
                return "Expired link", 400
        
            return render_template("_reset_password.html", key=reset_key)
        except Exception as ex:
            ic(ex)
            if "db" in locals(): db.rollback()
            if ex.args[1] == 400: return ex.args[0], 400
            return "Cannot reset password"
        finally:
            if "cursor" in locals(): cursor.close()
            if "db" in locals(): db.close()

    if request.method == "POST":
        try:
            reset_key = request.form.get("reset_key", "").strip()
            x.validate_uuid4_without_dashes(reset_key)

            user_password = x.validate_user_password()
            user_password_confirm = x.validate_user_password_confirm()

            if user_password != user_password_confirm:
                raise Exception ("Passwords do not match", 400)
            
            db, cursor = x.db()
            q = "SELECT user_pk FROM users WHERE user_reset_password_key = %s"
            cursor.execute(q, (reset_key,))
            user = cursor.fetchone()

            if not user:
                raise Exception ("Invalid or expired reset link", 400)
            
            user_pk = user["user_pk"]
            hashed = generate_password_hash(user_password)

            q = "UPDATE users SET user_password = %s, user_reset_password_key = '' WHERE user_pk = %s"
            cursor.execute(q, (hashed, user_pk))

            db.commit()

            return redirect(url_for('login'))
            # return f"""<mixhtml mix-redirect="{url_for('login')}"></mixhtml>"""
        
        except Exception as ex:
            ic(ex)
            if "db" in locals(): db.rollback()
            if len(ex.args) > 1 and ex.args[1] == 400:
                return ex.args[0], 400
            return "Cannot reset password", 500
        finally:
            if "cursor" in locals(): cursor.close()
            if "db" in locals(): db.close()
        


##############################
@app.get("/logout")
def logout():
    try:
        session.clear()
        return redirect(url_for("login"))
    except Exception as ex:
        ic(ex)
        return "error"
    finally:
        pass



##############################
@app.get("/home-comp")
def home_comp():
    try:

        user = session.get("user", "")
        if not user: return "error"
        db, cursor = x.db()
        q = "SELECT * FROM users JOIN posts ON user_pk = post_user_fk ORDER BY RAND() LIMIT 5"
        cursor.execute(q)
        tweets = cursor.fetchall()
        ic(tweets)

        html = render_template("_home_comp.html", tweets=tweets)
        return f"""<mixhtml mix-update="main">{ html }</mixhtml>"""
    except Exception as ex:
        ic(ex)
        return "error"
    finally:
        pass


##############################
@app.get("/profile")
def profile():
    try:
        user = session.get("user", "")
        if not user: return "error"
        q = "SELECT * FROM users WHERE user_pk = %s"
        db, cursor = x.db()
        cursor.execute(q, (user["user_pk"],))
        user = cursor.fetchone()
        profile_html = render_template("_profile.html", x=x, user=user)
        return f"""<browser mix-update="main">{ profile_html }</browser>"""
    except Exception as ex:
        ic(ex)
        return "error"
    finally:
        pass

##############################
@app.get("/users")
def users():
    try:
        admin = session.get("user")
        if not admin or admin.get("user_role", "").lower() != "admin":
            return f"""<browser mix-redirect="/home"></browser>"""

        # Hent alle brugere
        db, cursor = x.db()
        q = "SELECT * FROM users WHERE user_role = 'user'"
        cursor.execute(q)
        users = cursor.fetchall()

        users_html = render_template("_users.html", users=users)
        return f"""<browser mix-update="main">{ users_html }</browser>"""
    
    except Exception as ex:
        ic(ex)
        return "error"
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()

##############################
@app.post("/block_user")
def block_user():
    try:
        admin = session.get("user")
        if not admin or admin.get("user_role", "").lower() != "admin":
            return f"""<browser mix-redirect="/home"></browser>"""
        
        user_pk = request.form.get("user")
        db,cursor = x.db()

        # Hent brugerens info til mail
        q = "SELECT user_email, user_first_name FROM users WHERE user_pk = %s"
        cursor.execute(q, (user_pk,))
        user = cursor.fetchone()

        # Bloker brugeren
        q = "UPDATE users SET user_blocked = 1 WHERE user_pk = %s"
        cursor.execute(q, (user_pk,))
        db.commit()

        # Send email
        if user: 
            email_user_blocked = render_template("_email_user_blocked.html", user_first_name=user["user_first_name"])
            x.send_email(user["user_email"], "Din konto er blevet blokeret", email_user_blocked)

        # Hent alle brugere igen
        q = "SELECT * FROM users WHERE user_role='user'"
        cursor.execute(q)
        users = cursor.fetchall()

        users_html = render_template("_users.html", users=users)
        return f"""<browser mix-update="main">{users_html}</browser>"""

    except Exception as ex:
            ic(ex)
            return "error"
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()

##############################
@app.post("/unblock_user")
def unblock_user():
    try:
        user = session.get("user")
        if not user or user.get("user_role", "").lower() != "admin":
            return f"""<browser mix-redirect="/home"></browser>"""
        
        user_pk = request.form.get("user")
        db,cursor = x.db()

        # Hent brugerens info til mail
        q = "SELECT user_email, user_first_name FROM users WHERE user_pk = %s"
        cursor.execute(q, (user_pk,))
        user = cursor.fetchone()

        # Unblock brugeren
        q = "UPDATE users SET user_blocked = 0 WHERE user_pk = %s"
        cursor.execute(q, (user_pk,))
        db.commit()

        # Send email
        if user:
            email_user_unblocked = render_template("_email_user_unblocked.html", user_first_name=user["user_first_name"])
            x.send_email(user["user_email"], "Din konto er blevet genaktiveret", email_user_unblocked)

        # Hent alle brugere igen
        q = "SELECT * FROM users WHERE user_role='user'"
        cursor.execute(q)
        users = cursor.fetchall()

        users_html = render_template("_users.html", users=users)
        return f"""<browser mix-update="main">{users_html}</browser>"""

    except Exception as ex:
            ic(ex)
            return "error"
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()

##############################
@app.post("/like-toggle")
def like_toggle():
    try:
        user = session.get("user", "")
        post_pk = request.form.get("post_pk")
        like_created_at = int(time.time())

        db, cursor = x.db()

        # Check om brugeren allerede har liket
        q = "SELECT 1 FROM likes WHERE user_fk = %s AND post_fk = %s"
        cursor.execute(q, (user["user_pk"], post_pk))
        already_liked = cursor.fetchone()

        if already_liked:
            q = "DELETE FROM likes WHERE user_fk=%s AND post_fk=%s"
            cursor.execute(q, (user["user_pk"], post_pk))
        else:
            q = "INSERT INTO likes VALUES (%s, %s, %s)"
            cursor.execute(q, (user["user_pk"], post_pk, like_created_at))

        db.commit()

        # Hent opdateret like count
        q = "SELECT post_total_likes FROM posts WHERE post_pk=%s"
        cursor.execute(q, (post_pk,))
        like_count = cursor.fetchone()["post_total_likes"]

        # Dynamisk opdatering efter brugerhandling
        icon_class = "fa-solid fa-heart" if not already_liked else "fa-regular fa-heart"

        html = f"""
        <span id='like_icon_{post_pk}'><i class='{icon_class}'></i></span>
        <span id='like_count_{post_pk}'>{like_count}</span>
        """

        return f"<mixhtml mix-update='#like_container_{post_pk}'>{html}</mixhtml>"

    except Exception as ex:
        ic(ex)
        return "error"
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()

##############################
@app.get("/posts")
def posts():
    try:
        admin = session.get("user")
        if not admin or admin.get("user_role", "").lower() != "admin":
            return f"""<browser mix-redirect="/home"></browser>"""

        # Hent alle posts
        db, cursor = x.db()
        q = "SELECT posts.*, users.user_username FROM posts JOIN users ON posts.post_user_fk = users.user_pk ORDER BY post_created_at DESC"
        cursor.execute(q)
        posts = cursor.fetchall()

        post_html = render_template("_posts.html", posts=posts)
        return f'<browser mix-update="main">{post_html}</browser>'
    
    except Exception as ex:
        ic(ex)
        return "error"
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()

##############################
@app.post("/block-post")
def block_post():
    try: 
        user = session.get("user")
        if not user or user.get("user_role") != "admin":
            return '<browser mix-redirect="/home"></browser>'
        
        post_pk = request.form.get("post")
        db,cursor = x.db()

        # Hent brugerens info til mail
        q = "SELECT users.user_email, users.user_first_name FROM users JOIN posts ON users.user_pk = posts.post_user_fk WHERE posts.post_pk = %s"
        cursor.execute(q, (post_pk,))
        user = cursor.fetchone()

        # Bloker posten
        q = "UPDATE posts SET post_blocked = 1 WHERE post_pk = %s"
        cursor.execute(q, (post_pk,))
        db.commit()

        # Send mail
        if user: 
            email_post_blocked = render_template("_email_post_blocked.html", user_first_name=user["user_first_name"])
            x.send_email(user["user_email"], "Din post er blevet blokeret", email_post_blocked)

        # Hent alle posts igen
        q = "SELECT * FROM posts ORDER BY post_created_at DESC"
        cursor.execute(q)
        posts = cursor.fetchall()

        post_html = render_template("_posts.html", posts=posts)
        return f"""<browser mix-update="main">{post_html}</browser>"""

    except Exception as ex:
            ic(ex)
            return "error"
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()  

##############################
@app.post("/unblock-post")
def unblock_post():
    try: 
        user = session.get("user")
        if not user or user.get("user_role") != "admin":
            return '<browser mix-redirect="/home"></browser>'
        
        post_pk = request.form.get("post")
        db,cursor = x.db()

        # Hent brugerens info til mail
        q = "SELECT users.user_email, users.user_first_name FROM users JOIN posts ON users.user_pk = posts.post_user_fk WHERE posts.post_pk = %s"
        cursor.execute(q, (post_pk,))
        user = cursor.fetchone()

        # Fjern blokering
        q = "UPDATE posts SET post_blocked = 0 WHERE post_pk = %s"
        cursor.execute(q, (post_pk,))
        db.commit()

        # Send mail
        if user: 
            email_post_unblocked = render_template("_email_post_unblocked.html", user_first_name=user["user_first_name"])
            x.send_email(user["user_email"], "Din post er blevet blokeret", email_post_unblocked)

        # Hent alle posts igen
        q = "SELECT * FROM posts ORDER BY post_created_at DESC"
        cursor.execute(q)
        posts = cursor.fetchall()

        post_html = render_template("_posts.html", posts=posts)
        return f"""<browser mix-update="main">{post_html}</browser>"""

    except Exception as ex:
            ic(ex)
            return "error"
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()  
        

##############################
@app.route("/api-create-post", methods=["POST"])
def api_create_post():
    try:
        user = session.get("user", "")
        if not user: 
            return "invalid user"

        # hent tekst fra formular
        post_text = request.form.get("post", "").strip()
        post = None
        if post_text:
            post = x.validate_post(post_text)
            
        # hvis der ikke er tekst, kan det ikke udgives
        if not post:
            toast_error = render_template("___toast_error.html", message="Post must contain text")
            return f"<browser mix-bottom='#toast'>{toast_error}</browser>"
        
        # håndtering af billedfilen
        uploaded_file = request.files.get("upload_image")
        post_image_path = None
        if uploaded_file and uploaded_file.filename != "":
            if not allowed_file(uploaded_file.filename):
                toast_error = render_template("___toast_error.html", message="Invalid file type")
                return f"<browser mix-bottom='#toast'>{toast_error}</browser>"
            
            # Hent filtypen, lav et unikt filnavn, lav fuld sti og gem filen på serveren
            filetype = uploaded_file.filename.rsplit('.', 1)[1].lower()
            post_image_path = f"{uuid.uuid4().hex}.{filetype}"
            safe_path = os.path.join(UPLOAD_POST_FOLDER, post_image_path)
            uploaded_file.save(safe_path)
        
        post_pk = uuid.uuid4().hex
        post_blocked = 0
        post_total_likes = 0
        post_total_comments = 0
        post_created_at = int(time.time())
        post_updated_at = 0
        post_deleted_at = 0

        db, cursor = x.db()
        q = "INSERT INTO posts VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
        cursor.execute(q, (post_pk, post_blocked, user["user_pk"] , post, post_total_likes, post_total_comments, post_image_path, post_created_at, post_updated_at, post_deleted_at))
        db.commit()
        
        toast_ok = render_template("___toast_ok.html", message="The world is reading your post !")
        tweet = {
            "user_first_name": user["user_first_name"],
            "user_last_name": user["user_last_name"],
            "user_username": user["user_username"],
            "user_avatar_path": user["user_avatar_path"],
            "post_message": post,
            "post_image_path": post_image_path
        }

        html_post_container = render_template("___post_container.html")
        html_post = render_template("_tweet.html", tweet=tweet)

        return f"""
            <browser mix-bottom="#toast">{toast_ok}</browser>
            <browser mix-top="#posts">{html_post}</browser>
            <browser mix-replace="#post_container">{html_post_container}</browser>
        """
    
    except Exception as ex:
        ic(ex)
        if "db" in locals(): db.rollback()

        # User errors
        if "x-error post" in str(ex):
            toast_error = render_template("___toast_error.html", message=f"Post - {x.POST_MIN_LEN} to {x.POST_MAX_LEN} characters")
            return f"""<browser mix-bottom="#toast">{toast_error}</browser>"""

        # System or developer error
        toast_error = render_template("___toast_error.html", message="System under maintenance")
        return f"""<browser mix-bottom="#toast">{ toast_error }</browser>""", 500

    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()    

##############################
@app.route("/delete-post", methods=["DELETE"])
def delete_post():
    try: 
        user = session.get("user")
        if not user:
            return "invalid user"
        
        post_pk = request.args.get("post_pk")
        if not post_pk:
            return "Missing post"
        
        post_deleted_at = int(time.time())

        db, cursor = x.db()
        q = "UPDATE posts SET post_deleted_at = %s WHERE post_pk = %s AND post_user_fk = %s"
        cursor.execute(q, (post_deleted_at, post_pk, user["user_pk"]))
        db.commit()

        return f'<mixhtml mix-remove="#post_{post_pk}"></mixhtml>'
    
    except Exception as ex:
        ic(ex)
        if "db" in locals(): db.rollback()
        return "Could not delete post", 500

    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()  

##############################
@app.route("/api-update-profile", methods=["POST"])
def api_update_profile():

    try:

        user = session.get("user", "")
        if not user: return "invalid user"

        # Validate
        user_email = x.validate_user_email()
        user_username = x.validate_user_username()
        user_first_name = x.validate_user_first_name()

        # Hent den uploadede fil fra formularen
        avatar_file = request.files.get("user_avatar_image")
        # Placeholder - bliver sat til nyt filnavn, hvis brugeren uploader et billede
        user_avatar_path = None

        # Tjek at der er valgt en fil, og at den ikke er tom
        if avatar_file and avatar_file.filename != "":
            # Er filtypen tilladt?
            if not allowed_file(avatar_file.filename):
                raise Exception ("Invalid filetype", 400)
            
            # Hent filtypen, lav et unikt filnavn, lav fuld sti og gem filen på serveren
            filetype = avatar_file.filename.rsplit('.', 1)[1].lower()
            user_avatar_path = f"{uuid.uuid4().hex}.{filetype}"
            save_path = os.path.join(UPLOAD_FOLDER, user_avatar_path)
            avatar_file.save(save_path)

        # Connect to the database
        db, cursor = x.db()
        if user_avatar_path:
            q = "UPDATE users SET user_email = %s, user_username = %s, user_first_name = %s, user_avatar_path = %s WHERE user_pk = %s"
            cursor.execute(q, (user_email, user_username, user_first_name, user_avatar_path, user["user_pk"]))
        else:
            q = "UPDATE users SET user_email = %s, user_username = %s, user_first_name = %s WHERE user_pk = %s"
            cursor.execute(q, (user_email, user_username, user_first_name, user["user_pk"]))
        db.commit()

        # Response to the browser
        toast_ok = render_template("___toast_ok.html", message="Profile updated successfully")
        return f"""
            <browser mix-bottom="#toast">{toast_ok}</browser>
            <browser mix-update="#profile_tag .name">{user_first_name}</browser>
            <browser mix-update="#profile_tag .handle">{user_username}</browser>
            <browser mix-update="#profile_tag .picture">{user_avatar_path}</browser>
            
        """, 200
    except Exception as ex:
        ic(ex)
        # User errors
        if len(ex.args) > 1 and ex.args[1] == 400:
            toast_error = render_template("___toast_error.html", message=ex.args[0])
            return f"""<mixhtml mix-update="#toast">{ toast_error }</mixhtml>""", 400
        
        # Database errors
        if "Duplicate entry" and user_email in str(ex): 
            toast_error = render_template("___toast_error.html", message="Email already registered")
            return f"""<mixhtml mix-update="#toast">{ toast_error }</mixhtml>""", 400
        if "Duplicate entry" and user_username in str(ex): 
            toast_error = render_template("___toast_error.html", message="Username already registered")
            return f"""<mixhtml mix-update="#toast">{ toast_error }</mixhtml>""", 400
        
        # System or developer error
        toast_error = render_template("___toast_error.html", message="System under maintenance")
        return f"""<mixhtml mix-bottom="#toast">{ toast_error }</mixhtml>""", 500

    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()

##############################
@app.route("/delete-profile", methods=["DELETE"])
def delete_profile():
    try:
        user = session.get("user", "")
        db, cursor = x.db()
        q = """SELECT user_pk, user_created_at, 
        user_total_followers AS archived_followers_count, 
        user_total_following AS archived_following_count, 
        (SELECT COUNT(*) FROM posts WHERE post_user_fk = user_pk) AS archived_posts_count,
        (SELECT COUNT(*) FROM comments WHERE comment_user_fk = user_pk) AS archived_comments_count,
        (SELECT COUNT(*) FROM likes WHERE likes.user_fk = user_pk) AS archived_likes_count
        FROM users WHERE user_pk = %s
        """
        cursor.execute(q, (user["user_pk"],))
        archived_user = cursor.fetchone()

        q = "INSERT INTO archived_users VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
        cursor.execute(q, (user["user_pk"], archived_user["archived_posts_count"], archived_user["archived_comments_count"], archived_user["archived_likes_count"], archived_user["archived_followers_count"], archived_user["archived_following_count"], archived_user["user_created_at"], int(time.time())))
        
        q = "DELETE FROM users WHERE user_pk = %s"
        cursor.execute(q, (user["user_pk"],))
        db.commit()
        return f"""<browser mix-redirect="/signup"></browser>"""
        # return redirect(url_for('signup'))
    except Exception as ex:
        ic(ex)
        return "Error: deleting profile", 500
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()

##############################
@app.post("/api-search")
def api_search():
    try:
        # TODO: The input search_for must be validated
        search_for = request.form.get("search_for", "")
        if not search_for: return """empty search field""", 400
        part_of_query = f"%{search_for}%"
        ic(search_for)
        db, cursor = x.db()
        q = "SELECT * FROM users WHERE user_username LIKE %s"
        cursor.execute(q, (part_of_query,))
        users = cursor.fetchall()
        return jsonify(users)
    except Exception as ex:
        ic(ex)
        return str(ex)
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()



##############################
@app.get("/get-data-from-sheet")
def get_data_from_sheet():
    try:

        # Check if the admin is running this end-point, else show error

        # flaskwebmail
        # Create a google sheet
        # share and make it visible to "anyone with the link"
        # In the link, find the ID of the sheet. Here: 1aPqzumjNp0BwvKuYPBZwel88UO-OC_c9AEMFVsCw1qU
        # Replace the ID in the 2 places bellow
        url= f"https://docs.google.com/spreadsheets/d/{x.google_spread_sheet_key}/export?format=csv&id={x.google_spread_sheet_key}"
        res=requests.get(url=url)
        # ic(res.text) # contains the csv text structure
        csv_text = res.content.decode('utf-8')
        csv_file = io.StringIO(csv_text) # Use StringIO to treat the string as a file
        
        # Initialize an empty list to store the data
        data = {}

        # Read the CSV data
        reader = csv.DictReader(csv_file)
        ic(reader)
        # Convert each row into the desired structure
        for row in reader:
            item = {
                    'english': row['english'],
                    'danish': row['danish'],
                    'spanish': row['spanish']
                
            }
            # Append the dictionary to the list
            data[row['key']] = (item)

        # Convert the data to JSON
        json_data = json.dumps(data, ensure_ascii=False, indent=4) 
        # ic(data)

        # Save data to the file
        with open("dictionary.json", 'w', encoding='utf-8') as f:
            f.write(json_data) # skriv JSON-strengen til filen dictionary.json

        return "ok"
    except Exception as ex:
        ic(ex)
        return str(ex)
    finally:
        pass

@app.route("/languages", methods=["GET", "POST"])
def languages():
    try:
        admin = session.get("user")
        if not admin or admin.get("user_role", "").lower() != "admin":
            return '<browser mix-redirect="/home"></browser>'

        # Hvis det er POST, opdater fra Google Sheet
        if request.method == "POST":
            get_data_from_sheet()
            toast_ok = render_template("___toast_ok.html", message="Languages are updated!")
            return f"""<mixhtml mix-update="#toast">{toast_ok}</mixhtml>"""

        # Læs dictionary fra fil
        with open("dictionary.json", encoding="utf-8") as f:
            data = json.load(f) # konverter JSON-filen tilbage til et Python dictionary

        languages_html = render_template("_languages.html", languages=data)
        return f"""<browser mix-update="main">{languages_html}</browser>"""


    except Exception as ex:
        ic(ex)
        return "error"