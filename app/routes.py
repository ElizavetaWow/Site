from flask import render_template, flash, redirect, url_for, request, g
from app import app, db
from app.forms import LoginForm, RegistrationForm, EditProfileForm, PostForm  
from app.forms import ResetPasswordRequestForm, CheckMasterForm
from app.forms import ResetPasswordForm, AddScheduleForm, ConfirmForm
from app.models import User, Post, Master, Shedule
from app.email import send_password_reset_email
from flask_babel import _, get_locale
from flask_login import current_user, login_user, logout_user, login_required
from werkzeug.urls import url_parse
from datetime import datetime
from guess_language import guess_language
from werkzeug.security import generate_password_hash
import re


@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()
    g.locale = str(get_locale()) 


@app.route('/', methods = ['GET', 'POST'])
@app.route('/index', methods = ['GET', 'POST'])
def index():
    for v in Shedule.query.all():
        v.cleaning()  
    page = request.args.get('page', 1, type = int)
    users = User.query.all()
    u_id = None
    masters = Master.query.filter(Master.user_id != None).paginate(
        page, app.config['POSTS_PER_PAGE'], False)
    next_url = (url_for('index', page = masters.next_num)
                if masters.has_next else None)
    prev_url = (url_for('index', page = masters.prev_num)
                if masters.has_prev else None)
    return render_template('index.html', title = _('Home'),
                           masters = masters.items, users = users,
                           next_url = next_url, prev_url = prev_url)


@app.route('/blog', methods = ['GET', 'POST'])
def blog():
    form = PostForm()
    if form.validate_on_submit():
        language = guess_language(form.post.data)
        if language == 'UNKNOWN' or len(language) > 5:
            language = ''
        post = Post(body = form.post.data, author = current_user,
                    language = language)
        db.session.add(post)
        db.session.commit()
        flash(_('Your post is now live!'))
        return redirect(url_for('blog'))
    page = request.args.get('page', 1, type = int)
    posts = Post.query.order_by(Post.timestamp.desc()).paginate(
        page, app.config['POSTS_PER_PAGE'], False)
    next_url = (url_for('blog', page = posts.next_num)
                if posts.has_next else None)
    prev_url = (url_for('blog', page = posts.prev_num)
                if posts.has_prev else None)
    return render_template('blog.html', title = _('Blog'), form = form,
                           posts = posts.items, next_url = next_url,
                           prev_url = prev_url)


@app.route('/user/<username>', methods = ['GET', 'POST'])
@login_required
def user(username):
    form = PostForm()
    if form.validate_on_submit():
        language = guess_language(form.post.data)
        if language == 'UNKNOWN' or len(language) > 5:
            language = ''
        post = Post(body = form.post.data, author = current_user,
                    language = language)
        db.session.add(post)
        db.session.commit()
        flash(_('Your post is now live!'))
        return redirect(url_for('user', username = current_user.username))
    user = User.query.filter_by(username = username).first_or_404()
    page = request.args.get('page', 1, type = int)
    posts = user.posts.order_by(Post.timestamp.desc()).paginate(
        page, app.config['POSTS_PER_PAGE'], False)
    next_url = (url_for('user', username = user.username, page = posts.next_num)
                if posts.has_next else None)
    prev_url = (url_for('user', username = user.username, page = posts.prev_num)
                if posts.has_prev else None)
    return render_template('user.html', form = form, user = user,
                           posts = posts.items, next_url = next_url,
                           prev_url = prev_url, title = user.username)


@app.route('/edit_profile', methods = ['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm(current_user.username)
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.about_me = form.about_me.data
        db.session.commit()
        if form.master.data:
            return redirect(url_for('check_master'))
        flash(_('Your changes have been saved.'))
        return redirect(url_for('edit_profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', title = _('Edit Profile'),
                           form = form)


@app.route('/check_master/', methods = ['GET', 'POST'])  
@login_required 
def check_master():  
    form = CheckMasterForm()
    if form.validate_on_submit():
        if form.secret_key.data == "":
            return redirect(url_for('edit_profile'))
        m = Master.query.filter_by(secret_key = form.secret_key.data).first()
        if m and m.master == current_user.username:
            m.user_id = current_user.id
            current_user.master_id = m.id
            m.specialization = form.specialization.data
            db.session.commit()
            flash(_('You have confirmed your status.'))
        else:
            flash(_('You are not a master or your secret key is not right.'))
        return redirect(url_for('edit_profile'))
    return render_template('check_master.html', title = _('Check master'),
                           form = form)   


@app.route('/add_variant/<master_id>', methods = ['GET', 'POST'])
@login_required
def add_variant(master_id):
    master = Master.query.filter_by(id = master_id).first()
    form = AddScheduleForm()
    if form.validate_on_submit():
        if not re.fullmatch(r'\d{2}\.\d{2}\.\d{4}', form.date.data):
            flash(_('The date format is incorrect.'))
            return redirect(url_for('user', username = master.master))
        if not re.fullmatch(r'\d{2}:\d{2}', form.time.data):
            flash(_('The time format is incorrect.'))
            return redirect(url_for('user', username = master.master))
        day, month, year = form.date.data.split('.')
        hour, minute = form.time.data.split(':')
        if int(hour) < 7 or int(hour) > 23:
            flash(_('It is not a working hour.'))
            return redirect(url_for('user', username = master.master))
        try:
            date_time = datetime(int(year), int(month), int(day), int(hour)-3,
                                 int(minute))
        except ValueError:
            flash(_('Date and time are incorrect.'))
            return redirect(url_for('user', username = master.master))
        s_check = Shedule.query.filter_by(master_id = master_id,
                                          date_time = date_time).first()
        if not s_check:
            s = Shedule(master_id = master_id, date_time = date_time,
                        choosen = False)
            db.session.add(s)
            db.session.commit()
            flash(_('You have added new schedule variant!'))
        else:
            flash(_('This variant is already added.'))
        return redirect(url_for('user', username = master.master))
    return render_template('add_variant.html', form = form,
                           title = _('Add Schedule Variant'))


@app.route('/to_schedule/<master_id>', methods = ['GET', 'POST'])
@login_required
def to_schedule(master_id):
    master = Master.query.filter_by(id = master_id).first_or_404()
    page = request.args.get('page', 1, type = int)
    for v in Shedule.query.all():
        v.cleaning()    
    variants = master.variants.filter_by(choosen = False).order_by(
        Shedule.date_time.asc()).paginate(page, app.config['POSTS_PER_PAGE'], False)
    next_url = (url_for('schedule', master_id = master_id, page = variants.next_num)
                if variants.has_next else None)
    prev_url = (url_for('schedule', master_id = master_id, page = variants.prev_num)
                if variants.has_prev else None)
    return render_template('schedule.html', username = master.master,
                           variants = variants.items, next_url = next_url,
                           prev_url = prev_url, title = _('To schedule'))


@app.route('/choose/<variant>', methods = ['GET', 'POST'])
@login_required
def choose(variant): 
    master_id = int(variant.split('.')[0])
    date_time = datetime.strptime(variant.split('.')[1], "%Y-%m-%d %H:%M:%S")
    master_chosen = Master.query.filter_by(id = master_id).first()
    form = ConfirmForm()
    if form.validate_on_submit():
        s = Shedule.query.filter_by(master_id = master_id,
                                    date_time = date_time).first()
        s.choosen = True
        s.choosen_id = current_user.id
        s.person = current_user
        db.session.commit()
        flash(_('You scheduled successfully.'))
        return redirect(url_for('user', username = master_chosen.master))
    return render_template('conf.html', time = date_time,
                           form = form, title = _('Confirm the choice'), 
                           master = master_chosen.master,
                           heading = _('You want to schedule to the master'))


@app.route('/actual_schedules/<username>', methods = ['GET', 'POST'])
@login_required
def actual_schedules(username):
    for v in Shedule.query.all():
        v.cleaning()  
    user = User.query.filter_by(username = username).first()
    page = request.args.get('page', 1, type = int)
    variants = user.sh_vars.order_by(Shedule.date_time.asc()).paginate(
        page, app.config['POSTS_PER_PAGE'], False)
    next_url = (url_for('actual_schedules', username = user.username,
                        page = variants.next_num)
                if variants.has_next else None)
    prev_url = (url_for('actual_schedules', username = user.username,
                        page = variants.prev_num)
                if variants.has_prev else None)
    return render_template('actual_schedules.html', variants = variants.items,
                           title = _('Actual schedules'), user = user,
                           next_url = next_url, prev_url = prev_url)


@app.route('/followers/<username>', methods = ['GET', 'POST'])
@login_required
def followers(username):
    user = User.query.filter_by(username = username).first()
    page = request.args.get('page', 1, type = int)
    followers = user.followers.order_by(User.username.asc()).paginate(
        page, app.config['POSTS_PER_PAGE'], False)
    next_url = (url_for('follow_ers_ings', username = user.username,
                        page = followers.next_num)
                if followers.has_next else None)
    prev_url = (url_for('follow_ers_ings', username = user.username,
                        page = followers.prev_num)
                if followers.has_prev else None)
    return render_template('follow_ers_ings.html', title = _('Followers'), 
                           user = user, folls = followers.items,
                           next_url = next_url, prev_url = prev_url)


@app.route('/followings/<username>', methods = ['GET', 'POST'])
@login_required
def followings(username):
    user = User.query.filter_by(username = username).first()
    page = request.args.get('page', 1, type = int)
    followings = user.followed.order_by(User.username.asc()).paginate(
        page, app.config['POSTS_PER_PAGE'], False)
    next_url = (url_for('follow_ers_ings', username = user.username,
                        page = followings.next_num)
                if followings.has_next else None)
    prev_url = (url_for('follow_ers_ings', username = user.username,
                        page = followings.prev_num)
                if followings.has_prev else None)
    return render_template('follow_ers_ings.html', title = _('Following'), 
                           folls = followings.items, next_url = next_url,
                           prev_url = prev_url, user = user)


@app.route('/cancel/<variant_id>', methods = ['GET', 'POST'])
@login_required
def cancel(variant_id):
    variant = Shedule.query.filter_by(id = variant_id).first()
    form = ConfirmForm()
    if form.validate_on_submit():
        variant.choosen = False
        variant.choosen_id = None
        db.session.commit()
        return redirect(url_for('actual_schedules', username = current_user.username))
    return render_template('conf.html', title = _('Cancel the appointment'),
                           heading = _('You want to cancel the appointment to'),
                           master = variant.master.master, form = form,
                           time = variant.date_time)


@app.route('/follow/<username>')
@login_required
def follow(username):
    user = User.query.filter_by(username = username).first()
    if user is None:
        flash(_('User %(username)s not found.', username = username))
        return redirect(url_for('index'))
    if user == current_user:
        flash(_('You cannot follow yourself!'))
        return redirect(url_for('user', username = username))
    current_user.follow(user)
    db.session.commit()
    flash(_('You are following %(username)s!', username = username))
    return redirect(url_for('user', username = username))


@app.route('/unfollow/<username>')
@login_required
def unfollow(username):
    user = User.query.filter_by(username = username).first()
    if user is None:
        flash(_('User %(username)s not found.', username = username))
        return redirect(url_for('index'))
    if user == current_user:
        flash(_('You cannot unfollow yourself!'))
        return redirect(url_for('user', username = username))
    current_user.unfollow(user)
    db.session.commit()
    flash(_('You are not following %(username)s.', username = username))
    return redirect(url_for('user', username = username))


@app.route('/register', methods = ['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username = form.username.data, email = form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash(_('Congratulations, you are now a registered user!'))
        return redirect(url_for('login'))
    return render_template('register.html', title = _('Register'), form = form)


@app.route('/reset_password_request', methods = ['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email = form.email.data).first()
        if user:
            send_password_reset_email(user)
        flash(
            _('Check your email for the instructions to reset your password'))
        return redirect(url_for('login'))
    return render_template('reset_password_request.html', form = form,
                           title = _('Reset Password'))


@app.route('/reset_password/<token>', methods = ['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash(_('Your password has been reset.'))
        return redirect(url_for('login'))
    return render_template('reset_password.html', title = _('Reset password'),
                           form = form)


@app.route('/login', methods = ['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username = form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash(_('Invalid username or password'))
            return redirect(url_for('login'))
        login_user(user, remember = form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title = _('Sign In'), form = form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))