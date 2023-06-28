#import
from flask import Flask,render_template,redirect,flash,request
from flask_bcrypt import Bcrypt
from flask_login import UserMixin,login_user,logout_user,login_required,LoginManager,current_user
from flask_wtf import FlaskForm
from flask_sqlalchemy import SQLAlchemy
from wtforms import SubmitField,PasswordField,StringField,DateTimeField,EmailField,IntegerField
from wtforms.validators import DataRequired,Length,ValidationError
from datetime import datetime
# initialize
app = Flask(__name__)
app.config['SECRET_KEY']='THISISASECRETKEY'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

#TABLE USER
class User(db.Model,UserMixin):
    id = db.Column(db.Integer,primary_key=True)
    username = db.Column(db.String(20),nullable=False)
    password = db.Column(db.String(80),nullable=False)

    
    def validate_username(self,username):
        exisiting_username = User.query.filter_by(username = username.data).first()
        if exisiting_username:
            # raise ValidationError("THE USERNAME ALREADY EXISTS")
            flash("Username already exists")
            
#TABLE ADMIN
class Admin(db.Model,UserMixin):
    id = db.Column(db.Integer,primary_key=True)
    username = db.Column(db.String(20),nullable=False)
    password = db.Column(db.String(80),nullable=False)

#TABLE TASKS
class Tasks(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    task_name  =db.Column(db.String(50),nullable=False)
    date_created = db.Column(db.DateTime,default=datetime.utcnow)
    
    def __repr__(self):
        return '<Task %r>' % self.id
      
#USER REGISTER FORM
class UserRegisterForm(FlaskForm):
    username = StringField(validators=[DataRequired(),Length(max=20,min=4)],render_kw={"placeholder":"Username"})
    password = PasswordField(validators=[DataRequired(),Length(min=4,max=20)],render_kw={"placeholder":"Password"})
    submit = SubmitField("Register")
    
#USER LOGIN FORM
class UserLoginForm(FlaskForm):
    username = StringField(validators=[DataRequired(),Length(max=20,min=4)],render_kw={"placeholder":"Username"})
    password = PasswordField(validators=[DataRequired(),Length(min=4,max=20)],render_kw={"placeholder":"Password"})
    submit = SubmitField("Login")
    
#USER ADMIN FORM
class AdminLoginForm(FlaskForm):
    username = StringField(validators=[DataRequired(),Length(max=20,min=4)],render_kw={"placeholder":"Username"})
    password = PasswordField(validators=[DataRequired(),Length(min=4,max=20)],render_kw={"placeholder":"Password"})
    submit = SubmitField("Login")
    
#USER LOGIN MANAGER
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view="login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id)) 

# INDEX PAGE
@app.route('/',methods=['GET','POST'])
def index():
    return render_template('homepage.html')



# USER
@app.route('/user',methods=['POST','GET'])
def user():
    return render_template('user.html')

#USER/SIGNUP
@app.route('/user/signup',methods=['POST','GET'])
def user_signup():
    form = UserRegisterForm()
    
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data,password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/user/login')
    
    return render_template('/user/signup.html',form=form)

# USER/LOGIN
@app.route('/user/login',methods=['POST','GET'])
def login():
    form = UserLoginForm()
    user = User.query.filter_by(username = form.username.data).first()
    if user:
        if bcrypt.check_password_hash(user.password,form.password.data):
            login_user(user)
            return redirect('/user/dashboard')
            
    
    return render_template('/user/login.html',form=form)

#USER/DASHBOARD
@login_required
@app.route('/user/dashboard',methods=['POST','GET'])
def dashboard():
    username = current_user.username
    return render_template('/user/dashboard.html',username=username)

    
#ADMIN
@app.route('/admin',methods=['POST','GET'])
def admin():
    return render_template('admin.html')

#ADMIN/LOGIN
@app.route('/admin/login',methods=['POST','GET'])
def admin_login():
    form=AdminLoginForm()
    user = Admin.query.filter_by(username=form.username.data).first()
    if user:
        bcrypt.check_password_hash(user.password,form.password.data)
        login_user(user)
        return redirect('/admin/dashboard')
    return render_template('/admin/login.html',form=form)

#ADMIN/DASHBOARD
@login_required
@app.route('/admin/dashboard',methods=['GET','POST'])
def admin_dashboard():

    return render_template('/admin/dashboard.html')

#ADMIN/DASHBOARD/TASKS
@login_required
@app.route('/admin/dashboard/tasks',methods=['GET','POST'])
def admin_dashboard_tasks():
    if request.method == "POST":
        task_content = request.form['content']
        new_task = Tasks(task_name=task_content)
        db.session.add(new_task)
        db.session.commit()
        return redirect('/admin/dashboard/tasks')
    
    tasks = Tasks.query.order_by(Tasks.date_created).all()    
    return render_template('/admin/dashboard/tasks.html',tasks=tasks)

# ADMIN/DASHBOARD/TASKS/DELETE
@login_required
@app.route('/admin/dashboard/tasks/delete/<int:id>',methods=['GET','POST'])
def admin_dashboard_tasks_delete(id):
    deleted_item = Tasks.query.get_or_404(id)
    db.session.delete(deleted_item)
    db.session.commit()
    return redirect('/admin/dashboard/tasks')

# ADMIN/DASHBOARD/TASKS/UPDATE
@login_required
@app.route('/admin/dashboard/tasks/update/<int:id>',methods=['GET','POST'])
def admin_dashboard_tasks_update(id):
    updated_item=Tasks.query.get_or_404(id)
    if request.method == "POST":
        
        updated_item.task_name = request.form['content']
        db.session.commit()
        return redirect('/admin/dashboard/tasks')
    
    return render_template('/admin/dashboard/tasks_update.html',task=updated_item)
        
    

#LOGOUT
@app.route('/logout',methods=['GET','POST'])
def logout():
    logout_user()
    return redirect('/')


#debug
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        # admin= Admin(username="admin",password=bcrypt.generate_password_hash('admin&123'))
        # db.session.add(admin)
        # db.session.commit()
    app.run(debug=True)