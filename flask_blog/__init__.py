from flask import Flask
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_mail import Mail


application = Flask(__name__)
application.config['SECRET_KEY'] = '30674b7c1b98436fa4b197d064981689'
application.config["MONGO_URI"] = "mongodb+srv://dellpadaliya:padaliya178@cluster0-fbc3g.mongodb.net/blog?retryWrites=true&w=majority"
mongo = PyMongo(application)
db = mongo.db
bcrypt = Bcrypt(application)
application.config['MAIL_SERVER'] = 'smtp.googlemail.com'
application.config['MAIL_PORT'] = 587
application.config['MAIL_USE_TLS'] = True
application.config['MAIL_USERNAME'] = 'darshanpadaliya001@gmail.com'
application.config['MAIL_PASSWORD'] = 'darshan178'
mail = Mail(application)

current_user = {

    '_id' : None,
    'username' : None,
    'email' : None,
    'image_file' : None

}





from flask_blog import routes