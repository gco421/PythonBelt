# import Flask
from flask import Flask, render_template, redirect, request, session, flash
#import mySQL
from mysqlconnection import connectToMySQL
# the "re" module will let us perform some regular expression operations
import re
# create a regular expression object that we can use run operations on
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
app = Flask(__name__)
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)     # we are creating an object called bcrypt, 
                         # which is made by invoking the function Bcrypt with our app as an argument
app.secret_key = "b'\x17R\x81\x9a\xc4\xbcg\x9a\xbc\xc2K\xad\xd5\xb6\xec\r'"

@app.route("/")
def index():
    # use session to determine whether it's logged in or not
    if 'loggedin' not in session:
        session['loggedin']=False
    else:
        session['loggedin']=True
    return render_template("index.html", **session) #unwraps session so you don't need to refer to parent so now you can. you can use it on whatever route you need it to be on. so you can refer to session['f_n'] as f_n now.

@app.route("/registerprocess", methods=['POST'])
def register():
    #start mysql connection every time you need to query the mysql database
    mysql = connectToMySQL("logreg2")
    #takes data from client input and puts it into the server db in my sql
    # for key in request.form:
    # This is for if the form is blank. this doesn't show individual flash errors to inform the user so will now indicate individual flash messages for f_n, l_n instead.
        # if len(request.form[key])<1:
        #     flash("Please complete the form")

    #First name
    if len(request.form['f_n']) == 0:
        flash("First name cannot be blank!", 'f_n')
    if len(request.form['f_n']) <= 2:
        flash("First name must be 2+ characters")
    if not request.form['f_n'].isalpha():
        flash("Your first name cannot contain any numbers or symbols")
    
    #Last name
    if len(request.form['l_n']) == 0:
        flash("Last name cannot be blank!")
    if not request.form['l_n'].isalpha():
        flash("Your last name cannot contain any numbers or symbols")

    #Email regex
    if len(request.form['email']) == 0:
        flash("Email cannot be blank!", 'email')
    if not EMAIL_REGEX.match(request.form['email']):
        flash("Invalid Email Address!")
    #Is the email valid? Query the mysql database to find out
    query1 = "SELECT * FROM users WHERE email = %(email)s;"
    data = { "email" : request.form["email"] }
    result = mysql.query_db(query1, data)
    if result:
        flash("The email already exists")

    #Password: is it at least 8?
    if len(request.form['password']) == 0:
        flash("Password cannot be blank!", 'password')
    if len(request.form['password']) < 8:
        flash("Password needs to be at least 8 characters")
    #Validates passwords match for password confirmation
    if len(request.form['password_confirmation']) == 0:
        flash("Password confirmation section cannot be blank!", 'password_confirmation')
    if request.form['password_confirmation'] != request.form['password']:
        flash("Passwords don't match")

    #if there are any flash messages, you'll return to the index.html to fill out the registration form properly
    if '_flashes' in session.keys():
        #pass form data to sessions This saves the correct inputs for the user so they don't have to retype it and they would just fix the inputs with flash errors
        session['f_n'], session['l_n'], session['email'] = request.form['f_n'], request.form['l_n'], request.form['email']
        return redirect("/")

    else:
        mysql = connectToMySQL("logreg2")
        pw_hash = bcrypt.generate_password_hash(request.form['password'])
        query2 = "INSERT INTO users(f_n, l_n, email, password, created_at, updated_at) VALUES(%(f_n)s,%(l_n)s,%(email)s,%(password_hash)s, NOW(),NOW());"
        #We're telling the database this is the actual user input to populate the mysql table"
        data = {
            'f_n':request.form['f_n'],
            'l_n':request.form['l_n'],
            'email':request.form['email'],
            'password_hash':pw_hash
        }
        #Make the actual query to call/run Mysql
        results=mysql.query_db(query2, data)
        if results:
            return redirect('/loggedin')
    return redirect('/')

@app.route("/loginprocess", methods=['POST'])
def login():
    # see if the email provided exists in the database
    mysql = connectToMySQL("logreg2")
    query = "SELECT * FROM users WHERE email = %(email)s;"
    data = { "email" : request.form["email"] }
    result = mysql.query_db(query, data)
    if result:
    # assuming we only have one user with this username, the user would be first in the list we get back
    # of course, we should have some logic to prevent duplicates of usernames when we create users
    # use bcrypt's check_password_hash method, passing the hash from our database and the password from the form
        if bcrypt.check_password_hash(result[0]['password'], request.form['password']):
            # if we get True after checking the password, we may put the user id in session
            session['id'] = result[0]['id']
            # never render on a post, always redirect!
            return redirect('/loggedin')
        else:
            flash("Wrong login information")
    else:
        flash("Your email is not here")
    return redirect ('/')

@app.route("/loggedin")
def loggedin():
    if session['loggedin'] == True:
        return render_template("loggedin.html")
    else:
        return redirect('/')

@app.route("/loggedout", methods = ['POST'])
def loggedout():
    session.clear()
    return redirect ('/')

if __name__=="__main__":
    app.run(debug=True) 
