from flask import render_template, url_for, flash, redirect, request, session
from flask_blog.forms import RegistrationForm, LoginForm, UpdateAccountForm,PostForm, RequestResetForm, ResetPasswordForm
from flask_blog import application, db, bcrypt, current_user, mail
import uuid
import os
import secrets
from PIL import Image
from datetime import datetime
import numpy as np
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_mail import Message



def get_reset_token(username, expires_sec=1800):
    s = Serializer(application.config['SECRET_KEY'], expires_sec)
    return s.dumps({'user': username}).decode('utf-8')

def verify_reset_token(token):
    s = Serializer(application.config['SECRET_KEY'])
    try:
        username = s.loads(token)['user']
    except:
        return None
    user = db.user.find_one({ 'username' : username })
    return user



def image_file(id):
    user = db.user.find_one({ '_id' : id })
    x = user['image_file']
    return x

def username(id):
    user = db.user.find_one({ '_id' : id })
    x = user['username']
    return x



@application.route('/')
@application.route('/home')
def home():
    if not 'username' in session:
        flash('You are not loged in.', 'info')
        return redirect(url_for('login'))
    allposts = db.post.find().sort([("date_posted",-1)])
    user = db.user.find_one({ '_id' : current_user['_id'] })
    posts = []
    if 'following' in user:
        for post in allposts:
            if post['user_id'] in user['following']:
                posts.append(post)
        posts = np.array(posts)
        if posts.any():
            return render_template("home.html", title='Home', posts=posts, image_file=image_file, username=username, nopost=False)
        else:
            return render_template("home.html", title='Home', nopost=True)
    else:
        return render_template("home.html", title='Home', nopost=True)
        

@application.route('/about')
def about():
    if not 'username' in session:
        flash('You are not loged in.', 'info')
        return redirect(url_for('login'))
    return render_template("about.html", title="about", current_user=current_user)

@application.route("/register", methods=['GET', 'POST'])
def register():
    if 'username' in session:
        flash('You have already loged in.', 'info')
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        users = db.user
        users.insert({
            "username" : form.username.data,
            "email" : form.email.data,
            "password" : hashed_pw,
            "image_file" : "default.jpg"
        })
        flash(f'Your account has been created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@application.route("/login", methods=['GET', 'POST'])
def login():
    if 'username' in session:
        flash('You have already loged in.', 'info')
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = db.user.find_one({ "email" : form.email.data })
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('login'))    
        if user and bcrypt.check_password_hash(user["password"], form.password.data):
            session["username"] = user["username"]
            current_user["_id"] = user["_id"]
            current_user["username"] = user["username"]
            current_user["email"] = user["email"]
            current_user["image_file"] = user["image_file"]
            flash("You have loged in successfully","success")
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@application.route("/logout")
def logout():
    if 'username' in session:
        session.pop('username', None)
        current_user["_id"] = None
        current_user["username"] = None
        current_user["email"] = None
        current_user["image_file"] = None     
        flash('You have been loged out.', 'success')
        return redirect(url_for('login')) 
    else:
        flash('You are not logged in', 'info')
        return redirect(url_for('login')) 


def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(application.root_path, 'static/profile_pics', picture_fn)

    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn


@application.route("/account", methods=['GET', 'POST'])
def account():
    if 'username' in session:
        form = UpdateAccountForm()
        if form.validate_on_submit():
            if form.picture.data:
                picture_file = save_picture(form.picture.data)
                db.user.update_one({ 'username' : current_user['username'] }, { '$set' : { 'image_file' : picture_file } })
                current_user['image_file'] = picture_file
            db.user.update_one({ 'username' : current_user['username'] }, { '$set' : { 'username' : form.username.data } })
            db.user.update_one({ 'username' : current_user['username'] }, { '$set' : { 'email' : form.email.data } })
            current_user['username'] = form.username.data
            current_user['email'] = form.email.data
            flash('Your account has been updated!', 'success')
            return redirect(url_for('account'))
        elif request.method == 'GET':
            form.username.data = current_user['username']
            form.email.data = current_user['email']
        ac_user = db.user.find_one({ 'username' : current_user['username'] })
        posts = db.post.find({ 'user_id' : ac_user['_id'] })
        image = url_for('static', filename='profile_pics/' + image_file(ac_user['_id']))
        return render_template('account.html', title='Account', image_file=image_file, username=username, image=image, form=form, current_user=current_user, posts=posts)
    else:
        flash('You are not loged in.', 'info')
        return redirect(url_for('login')) 

@application.route("/post/new", methods=['GET', 'POST'])
def new_post():
    if not 'username' in session:
        flash('You are not loged in.', 'info')
        return redirect(url_for('login'))
    form = PostForm()
    if form.validate_on_submit():
        user = db.user.find_one({ 'username' : current_user['username'] })
        db.post.insert({
            "id": str(uuid.uuid4()),
            "title" : form.title.data,
            "content" : form.content.data,
            "date_posted" : datetime.utcnow(),
            "user_id": user['_id']
        })
        flash('Your post has been created!', 'success')
        return redirect(url_for('home'))
    return render_template('create_post.html', title='New Post', form=form, legend='New Post')

@application.route("/post/<post_id>")
def post(post_id):
    if not 'username' in session:
        flash('You are not loged in.', 'info')
        return redirect(url_for('login'))
    post = db.post.find_one_or_404({ "id" : post_id })
    return render_template('post.html', title=post['title'], post=post, username=username, image_file=image_file)


@application.route("/post/<post_id>/update", methods=['GET', 'POST'])
def update_post(post_id):
    if not 'username' in session:
        flash('You are not loged in.', 'info')
        return redirect(url_for('login'))
    post = db.post.find_one_or_404({ "id" : post_id })
    form  = PostForm()
    if form.validate_on_submit():
        db.post.update_one({ '_id' : post['_id'] }, { '$set' : { 'title' : form.title.data } })
        db.post.update_one({ '_id' : post['_id'] }, { '$set' : { 'content' : form.content.data } })
        flash('Your post has been updated!', 'success')
        return redirect(url_for('post', post_id=post_id))
    elif request.method == 'GET':
        form.title.data = post['title']
        form.content.data = post['content']
    return render_template('create_post.html', title='Update Post', form=form, post=post, legend='Update Post')


@application.route("/post/<post_id>/delete178", methods=['POST'])
def delete_post(post_id):
    if not 'username' in session:
        flash('You are not loged in.', 'info')
        return redirect(url_for('login'))
    db.post.delete_one({ 'id' : post_id })
    flash('Your post has been deleted!', 'success')
    return redirect(url_for('account'))


@application.route("/profile/<username>", methods=['GET', 'POST'])
def profile(username):
    if not 'username' in session:
        flash('You are not loged in.', 'info')
        return redirect(url_for('login'))
    user = db.user.find_one_or_404({ 'username' : username })
    posts = db.post.find({ 'user_id' : user['_id'] }).sort([("date_posted",-1)])
    return render_template("profile.html", posts=posts, user=user,title=username, current_user=current_user)


@application.route("/find_bloger", methods=['GET', 'POST'])
def find_bloger():
    if not 'username' in session:
        flash('You are not loged in.', 'info')
        return redirect(url_for('login'))
    users = db.user.find()
    return render_template("find_bloger.html", users=users, title="Find Bloger", current_user=current_user)


@application.route("/follow/<root_path>/<bloger_name>", methods=['GET', 'POST'])
def follow(bloger_name,root_path):
    if not 'username' in session:
        flash('You are not loged in.', 'info')
        return redirect(url_for('login'))
    bloger = db.user.find_one({ 'username' : bloger_name })
    db.user.update(
        { 'username' : current_user['username'] },
        { '$push' : { 'following' : bloger['_id'] } }
    )
    db.user.update(
        { 'username' : bloger_name },
        { '$push' : { 'followers' : current_user['_id'] } }
    )
    if root_path == 'find_bloger':
        return redirect(url_for('find_bloger'))
    else:
        return redirect(url_for('profile', username=bloger_name))


@application.route("/unfollow/<root_path>/<bloger_name>", methods=['GET', 'POST'])
def unfollow(bloger_name,root_path):
    if not 'username' in session:
        flash('You are not loged in.', 'info')
        return redirect(url_for('login'))
    bloger = db.user.find_one({ 'username' : bloger_name })
    db.user.update(
        { 'username' : current_user['username'] },
        { '$pull' : { 'following' : bloger['_id'] } }
    )
    db.user.update(
        { 'username' : bloger_name },
        { '$pull' : { 'followers' : current_user['_id'] } }
    )
    if root_path == 'find_bloger':
        return redirect(url_for('find_bloger'))
    else:
        return redirect(url_for('profile', username=bloger_name))




def send_reset_email(user):
    token = get_reset_token(username=user['username'])
    msg = Message('Password Reset Request',
                  sender='darshanpadaliya001@gmail.com',
                  recipients=[user['email']])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}
If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)


@application.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if 'username' in session:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = db.user.find_one({ 'email' : form.email.data })
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)


@application.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if 'username' in session:
        return redirect(url_for('home'))
    user = verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        db.user.update_one({ 'username' : user['username'] }, { '$set' : { 'password' : hashed_password } })
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)







