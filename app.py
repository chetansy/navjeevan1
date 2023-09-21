# -- coding: utf-8 --
"""
Created on Fri Jul  7 12:19:26 2023

@author: Payal
"""
import random
import psycopg2
import psycopg2.extras
import re 
import cgi
form = cgi.FieldStorage()
import urllib.request
import urllib.parse
from flask import Flask, request, session, redirect, url_for, render_template, flash, jsonify
import psycopg2 
import psycopg2.extras
import re 
from werkzeug.security import generate_password_hash, check_password_hash

from flask_mail import *  
import smtplib
from random import *
import logging  
import datetime
from datetime import datetime,timedelta
import json
import pandas as pd
import sklearn
from sklearn.preprocessing import OneHotEncoder, MinMaxScaler
import pickle

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestRegressor, GradientBoostingRegressor
from sklearn.metrics import mean_squared_error

import pdfkit
from jinja2 import Environment, FileSystemLoader
from prettytable import PrettyTable
from bs4 import BeautifulSoup
app = Flask(__name__)
mail = Mail(app)


#app.config["MAIL_SERVER"]='smtpout.secureserver.net'
#app.config["MAIL_PORT"] = 587      
#app.config["MAIL_USERNAME"] = 'pallavi.uike@creditsiddhi.com'  
#app.config['MAIL_PASSWORD'] = 'psmsuuved06#'  

app.config["SECRET_KEY"] = 'root'
app.config["MAIL_SERVER"]='smtp.googlemail.com'
app.config["MAIL_USE_TLS"] = True      
app.config["MAIL_PORT"] = 587      
app.config["MAIL_USERNAME"] = 'navjeevan.creditsiddhi@gmail.com'  
app.config['MAIL_PASSWORD'] = 'endf ghdw unlj ajtc'  


mail = Mail(app)
#app.secret_key = 'root'
logging.basicConfig(level=logging.INFO)


app.config['SESSION_TYPE'] = 'filesystem'


DB_HOST = "dpg-ck5a6oeru70s739qi8ug-a"
DB_NAME = "navjeevan_data"
DB_USER = "navjeevan_data_user"
DB_PASS = "263sRonJ5pLLli2OfSN6YzptaWucb2jb"
DB_PORT = "5432"


from flask_mail import Message
from flask import render_template

    

conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST, port=DB_PORT)
conn.autocommit = True
cursor = conn.cursor()
 
# Password policy constants
MAX_LOGIN_ATTEMPTS = 3
PASSWORD_MIN_LENGTH = 8
PASSWORD_EXPIRY_DAYS = 90

def get_customer_id_for_user(email):
    try:
        cursor.execute("SELECT customer_id FROM login_details WHERE email = %s", (email,))
        customer_id = cursor.fetchone()
        
        if customer_id:
            print("custmer_id_functn:---------",customer_id[0])
            return customer_id[0]
        else:
            return None  # User not found

    except Exception as e:
        print(f"Error in get_customer_id_for_user: {e}")
        return None


#if customer_id:
#    print(f"Customer ID for {email} is {customer_id}")
#else:
#    print(f"User with email {email} not found.")


# Function to register a new user and return customer_id
def register_new_user(name, email, password):
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT customer_id FROM login_details WHERE email = %s", (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            return None

        # Insert the new user into the database
        cursor.execute("INSERT INTO customer_details (name, email, password) VALUES (%s, %s, %s)", (name, email, password))
        conn.commit()

        # Fetch the customer_id of the newly registered user
        cursor.execute("SELECT customer_id FROM customer_details WHERE email = %s", (email,))
        new_user = cursor.fetchone()

        if new_user:
            return new_user[0]
        else:
            return None

    except Exception as e:
        print(f"Error in register_new_user: {e}")
        return None


############################################################################################################


def get_neo_score(email):
	    customer_id = request.json.get('customer_id')
	    print("test0")
	    cursor.execute("SELECT customer_id FROM login_details WHERE email = %s", (email,))
	    custo_id = cursor.fetchone()
	    print("custo_id:--------------",custo_id[0])
	    customer_id = custo_id[0]
	    # Query data from the customer_details and eligibility_details tables
	    cursor.execute(f'SELECT * FROM customer_details WHERE customer_id = %s', (customer_id,))
	    df_customer = pd.DataFrame(cursor.fetchall(), columns=[desc[0] for desc in cursor.description])
	    print("test1")
	    
	    cursor.execute(f'SELECT cibil_score FROM eligibility_details WHERE customer_id = %s', (customer_id,))
	    df_eligibility = pd.DataFrame(cursor.fetchall(), columns=['cibil_score'])
	    print("test2")
	
	    # Combine the data into a single DataFrame
	    df = pd.concat([df_customer, df_eligibility], axis=1)
	    df.fillna(0,inplace=True)
	    print(df)
	    print("test3")
	
	    # Drop unnecessary columns
	    df.drop(columns=['customer_id', 'pan', 'pan_status','required_credit_amount'], inplace=True)
	    print("test4")
	    
	   # Loading later
	    with open('neo_score/neo_score_model_and_transformers1.pkl', 'rb') as f:
	        saved_objects = pickle.load(f)
	    
	    model = saved_objects['model']
	    print("model:------",model)
	    encoder = saved_objects['encoder']
	    print("encoder:----",encoder)
	    scaler = saved_objects['scaler']
	    print("scaler:-------",scaler)
	        
	    # Define the categorical columns
	    categorical_columns = ['designation', 'existing_emi', 'type_of_credit', 'industry']
	
	    new_data = df
	  
	    # Apply one-hot encoding using the same encoder
	    #encoder = OneHotEncoder()
	    one_hot_encoded_new = encoder.transform(new_data[categorical_columns])
	    new_data = new_data.drop(categorical_columns, axis=1)
	    new_data = pd.concat([new_data, pd.DataFrame(one_hot_encoded_new.toarray(), columns=encoder.get_feature_names_out(categorical_columns))], axis=1)
	    
	    # Apply min-max scaling using the same scaler
	    #scaler = MinMaxScaler()
	    new_data[new_data.columns.difference(['neo_score'])] = scaler.transform(new_data[new_data.columns.difference(['neo_score'])])
	
	
	    df = new_data
	
	    # Change the datatype to int32
	    #df = df.astype(np.int32)
	    #print(df)
	    print("test6")
	
	
	    # Apply the model to the DataFrame
	    neo_score = model.predict(df)
	
	    # Store the output in the eligibility_details table
	    cursor.execute(f'UPDATE eligibility_details SET neo_score = %s WHERE customer_id = %s', (neo_score[0], customer_id))
	
	    #return jsonify({'neo_score': neo_score[0]})
	    return neo_score[0]

def get_eligible_amount(email):
    
    customer_id = request.json.get('customer_id')
    print("test0")
    
    cursor.execute(f'SELECT customer_id FROM customer_details WHERE email = %s', (email,))
    custo_id = cursor.fetchone()
    print("custo_id:--------------",custo_id[0])
    # Query data from the customer_details and eligibility_details tables
    cursor.execute(f'SELECT * FROM customer_details WHERE customer_id = %s', (customer_id,))
    df_customer = pd.DataFrame(cursor.fetchall(), columns=[desc[0] for desc in cursor.description])
    print("test1")
    
    cursor.execute(f'SELECT cibil_score,neo_score FROM eligibility_details WHERE customer_id = %s', (customer_id,))
    df_eligibility = pd.DataFrame(cursor.fetchall(), columns=['cibil_score','neo_score'])
    print("test2")

    # Combine the data into a single DataFrame
    df = pd.concat([df_customer, df_eligibility], axis=1)
    #print(df)
    print("test3")

    # Drop unnecessary columns
    df.drop(columns=['customer_id', 'pan', 'pan_status','required_credit_amount'], inplace=True)
    print("test4")
    
   # Loading later
    with open('neo_score/eligible_amount_model_and_transformers1.pkl', 'rb') as f:
        saved_objects = pickle.load(f)
    
    model = saved_objects['model']
    encoder = saved_objects['encoder']
    scaler = saved_objects['scaler']
        
    # Define the categorical columns
    categorical_columns = ['designation', 'existing_emi', 'type_of_credit', 'industry']

    new_data = df
    
    
    
    # Apply one-hot encoding using the same encoder
    #encoder = OneHotEncoder()
    one_hot_encoded_new = encoder.transform(new_data[categorical_columns])
    new_data = new_data.drop(categorical_columns, axis=1)
    new_data = pd.concat([new_data, pd.DataFrame(one_hot_encoded_new.toarray(), columns=encoder.get_feature_names_out(categorical_columns))], axis=1)
    
    # Apply min-max scaling using the same scaler
    #scaler = MinMaxScaler()
    new_data[new_data.columns.difference(['eligible_amount'])] = scaler.transform(new_data[new_data.columns.difference(['eligible_amount'])])


    df = new_data.fillna(0)

    # Change the datatype to int32
    #df = df.astype(np.int32)
    #print(df)
    print("test6")


    # Apply the model to the DataFrame
    eligible_amount = model.predict(df)

    # Store the output in the eligibility_details table
    cursor.execute(f'UPDATE eligibility_details SET eligible_amount = %s WHERE customer_id = %s', (eligible_amount[0], customer_id))

    #return jsonify({'eligible_amount': eligible_amount[0]})
    return eligible_amount[0]
##########################################################################
@app.route('/', methods=['POST'])
def index():
	return 'Hello World'

############################ API for login page############################
@app.route('/login', methods=['POST'])
def login():
    email = request.json['email']
    password = request.json['password']
    print("email:----",email)
    print("password:----------",password)
    
    customer_id = get_customer_id_for_user(email) 
    # Set the customer_id in the session
    session['customer_id'] = customer_id
    
    
    cursor.execute("SELECT password, last_password_change FROM login_details WHERE email = %s", (email,))
    user_data = cursor.fetchone()

    if user_data:
        _hashed_password, last_password_change = user_data

        current_date = datetime.now()
        if last_password_change is None:
            return jsonify({'message': 'Last Password change date not found'}), 500

        expiration_date = last_password_change + timedelta(days=PASSWORD_EXPIRY_DAYS)
        if current_date > expiration_date:
            return jsonify({'message': 'Your password has expired. Please change your password.'}), 401

        if check_password_hash(_hashed_password, password):
            # Reset login attempts on successful login
            session['login_attempts'] = 0
            return jsonify({'message': 'Login successful'}), 200
        else:
            # Increment login attempts
            session['login_attempts'] = session.get('login_attempts', 0) + 1
            # Check if maximum login attempts reached
            if session['login_attempts'] >= MAX_LOGIN_ATTEMPTS:
                return jsonify({'message': 'Maximum login attempts exceeded. Please try again later.'}), 401        
            else:
                return jsonify({'message': 'Invalid password'}), 401
    else:
        return jsonify({'message':'User not found'}), 404

############################ API for signup page############################
@app.route('/signup', methods=['POST'])
def signup():
    request_data = request.json
    try:
        regex = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')  
      
        email = request_data.get('email')
        mobile = request_data.get('mobile')
    
        if re.fullmatch(regex, email):  
            print("The given mail is valid")  
            if mobile and len(str(mobile)) == 10:
                print("The mobile is valid")  
                signup_result = signup_with_credentials(request_data)
                print("signup_result:------------",signup_result['message'])
                if signup_result['message'] == "User signup successfully" :
                    print("Yes:---------")
                    if request_data['mobile'] and request_data['email']:
                        print("getting mobile:----",request_data['email'])
                        mobile_sendotp(request_data)
            
                        print("getting email:----")
                        email_sendotp1(request_data)
            
                return jsonify(signup_result)
            else:
                return jsonify({"status": "error", "message": "Invalid mobile number provided."})
        else:  
            print("The given mail is invalid")  
            return jsonify({"status": "error", "message": "The given mail is invalid."})
    except Exception as e:
        print("ERROR_Ssingup:----",e)
        return jsonify({"status": "error", "message": e})

def mobile_sendotp(data):
    print("mobile:----",data.get('mobile'))
    try:
        mobile = data.get('mobile')
        #customer_id = session.get('customer_id')
        
        otp = randint(100000, 999999)
        print("OTP:----",otp)
        cursor.execute(
            "UPDATE public.login_details "
            "SET otp = %s, otp_status = 'SENT', otp_generated_date_time = %s "
            "WHERE mobile = %s", 
            (otp, datetime.now(), mobile)
        )
        conn.commit()
        logging.info(f"OTP sent to mobile number: {mobile}")
        response_data = {"status": "success", "message": "OTP sent successfully."}
        return response_data

    except ValueError as ve:
        logging.error(f"ValueError: {ve}")
        print("Value Error in MobileOTP:---",ve)
        response_data = {"status": "error", "message": str(ve)}
        return response_data

    except Exception as e:
        logging.error(f"Exception: {e}")
        response_data = {"status": "error", "message": "An unexpected error occurred."}
        return response_data



def email_sendotp1(data):
    print("email:----",data.get('email'))
    try:
        email = data.get('email')
        #customer_id = session.get('customer_id')

        if not email:
            raise ValueError("Invalid email address provided.")
        email_otp = randint(100000, 999999)
        print("email_otp:----",email_otp)
        cursor.execute(
            "UPDATE public.login_details "
            "SET email_otp = %s, email_otp_status = 'SENT', email_otp_generated_date_time = %s "
            "WHERE email = %s", 
            (email_otp, datetime.now(), email)
        )
        conn.commit()
        #msg = Message('OTP', sender='pallaviuike140@gmail.com', recipients=[email])
        msg = Message("Send Mail Tutorial!",
		  sender="chetan0yewale@gmail.com",
		  recipients=[email])
        
        msg.body = "Your one-time password (OTP) is " + " " + str(email_otp)
        print("getting erorr:--------------------",msg.body)
        mail.send(msg)
        logging.info(f"OTP sent to registered email: {email}")
        print(f"OTP sent to registered email: {email}")
        response_data = {"status": "success", "message": "OTP sent successfully."}
        return response_data

    except ValueError as ve:
        logging.error(f"ValueError: {ve}")
        response_data = {"status": "error", "message": str(ve)}
        return response_data

    except Exception as e:
        logging.error(f"Exception: {e}")
        response_data = {"status": "error", "message": "An unexpected error occurred."}
        return response_data

def signup_with_credentials(data):
    try:
        name = data.get('name')
        email = data.get('email')
        mobile = data.get('mobile')
        password = data.get('password')
        #customer_id = session.get('customer_id',None)
        #customer_id = register_new_user(name, email, password)
        #if customer_id:
            # Set customer_id in the session
         #   session['customer_id'] = customer_id
        
        
        if not is_valid_password(password):
            response_data = {"status": "error", "message": "Invalid password"}
            jsonify(response_data), 400  # Return JSON response with a status code


        _hashed_password = generate_password_hash(password)

        try:
            current_date = datetime.now()
            cursor.execute("INSERT INTO login_details (name, email, mobile, password, last_password_change) VALUES (%s, %s, %s, %s, %s)", (name, email, mobile, _hashed_password, current_date))
            conn.commit()
            session['customer_id'] = get_customer_id_for_user(email)
            response_data = {"message": "User signup successfully"}
            return response_data  # Return JSON response with a status code

        except Exception as e:
            conn.rollback()  
            response_data = {"status": "error", "message": str(e)}
            return response_data # Return JSON response with a status code

        print("Records inserted.....")

    except Exception as e:
        logging.error(f"Exception: {e}")
        response_data = {"status": "error", "message": "An unexpected error occurred."}
        return response_data

def is_valid_password(password):
    if (
        len(password) < PASSWORD_MIN_LENGTH
        or not any(char.isupper() for char in password)
        or not any(char.isdigit() for char in password)
        or not any(char in "!@#$%^&*()_-+=<>,.?/:;{}[]|\\~" for char in password)
    ):
        return False
    return True
	



########################### API for LOGOUT PAGE ####################################
@app.route('/logout/')
def logout():
    session.clear()
    print("Logged out successfully!")
    return redirect(url_for('login'))

########################### API for sendOTP to Mobile ####################################
@app.route('/sendotp', methods=['POST'])
def send_otp():
    try:
        mobile = request.json.get('mobile')
        if not mobile or len(str(mobile)) != 10:
            raise ValueError("Invalid mobile number provided.")
       
        otp = random.randint(100000, 999999)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE public.login_details "
            "SET otp = %s, otp_status = 'SENT', otp_generated_date_time = %s "
            "WHERE mobile = %s", 
            (otp, datetime.now(), mobile)
        )
        if cursor.rowcount == 0:
            raise ValueError("Mobile number not found in the database.")
        conn.commit()
        logging.info(f"OTP sent to mobile number: {mobile}")
        return jsonify({"status": "success", "message": "OTP sent successfully."}), 200

    except ValueError as ve:
        logging.error(f"ValueError: {ve}")
        return jsonify({"status": "error", "message": str(ve)}), 400

    except Exception as e:
        logging.error(f"Exception: {e}")
        return jsonify({"status": "error", "message": "An unexpected error occurred."}), 500
     
########################### API for Mobile OTP verification ####################################
@app.route('/otp-verification', methods=['POST'])
def otp_verification():
    try:
        conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST, port=DB_PORT)
        cursor = conn.cursor()
        cursor.execute("SELECT customer_id,mobile FROM public.login_details ORDER BY customer_id DESC LIMIT 1" )
        cust_id_al = cursor.fetchall()
        conn.commit()
        print("MObile:--------",cust_id_al[0],cust_id_al[0][1])
        mobile = cust_id_al[0][1]
#        mobile = request.json.get('mobile')
        provided_otp = request.json.get('otp')
        print("provided_mobile_otp:--------",provided_otp)

        if not mobile or len(str(mobile)) != 10:
            raise ValueError("Invalid mobile number provided.")
        if not provided_otp or len(str(provided_otp)) != 6:
            raise ValueError("Invalid OTP provided.")

        cursor.execute(
            "SELECT otp, otp_status, otp_generated_date_time FROM public.login_details WHERE mobile = %s",
            (mobile,)
        )
        record = cursor.fetchone()
        if not record:
            raise ValueError("Mobile number not found in the database.")

        db_otp, otp_status, otp_generated_date_time = record
        if otp_status == "SENT":
            current_time = datetime.now()
            difference_in_minutes = (current_time - otp_generated_date_time).total_seconds() / 60
            print(difference_in_minutes)
            if difference_in_minutes > 10:
                cursor.execute(
                    "UPDATE public.login_details SET otp_status = 'EXPIRED' WHERE mobile = %s",
                    (mobile,)
                )
                conn.commit()
                return jsonify({"status": "error", "message": "OTP is Expired please re-generate otp again"}), 400
            else:
                if provided_otp == db_otp:
                    cursor.execute(
                        "UPDATE public.login_details SET otp_status = 'SUCCESS' WHERE mobile = %s",
                        (mobile,)
                    )
                    conn.commit()
                    return jsonify({"status": "success", "message": "OTP verification SUCCESS"}), 200
                else:
                    cursor.execute(
                        "UPDATE public.login_details SET otp_status = 'FAILED' WHERE mobile = %s",
                        (mobile,)
                    )
                    conn.commit()
                    return jsonify({"status": "error", "message": "Invalid OTP provided."}), 400
        else:
            return jsonify({"status": "error", "message": "OTP is Expired please re-generate otp again"}), 400

    except ValueError as ve:
        logging.error(f"ValueError: {ve}")
        return jsonify({"status": "error", "message": str(ve)}), 400

    except Exception as e:
        logging.error(f"Exception: {e}")
        return jsonify({"status": "error", "message": "An unexpected error occurred."}), 500
        
################################ Sent OPT to Email API ###################################
@app.route('/email_sendotp',methods = ["GET","POST"])  
def email_sendotp():  
    email = request.json["email"]  
    print(email)
    email_otp = randint(100000,999999) 
    
    cursor = conn.cursor()
    cursor.execute(
          "UPDATE public.login_details "
          "SET email_otp = %s, email_otp_status = 'SENT', email_otp_generated_date_time = %s "
          "WHERE email = %s", (email_otp, datetime.now(), email)
      )
    if cursor.rowcount == 0:
        raise ValueError("Please enter registerd email.")
    conn.commit() 
    msg = Message('OTP',sender = 'pallavi.uike@creditsiddhi.com', recipients = [email])  
    msg.body = "Your one time password(OTP) is " + " " + str(email_otp)
    mail.send(msg)  
    
    logging.info(f"OTP sent to registerd email: {email}")
    return jsonify({"status": "success", "message": "OTP sent successfully."}), 200

################################ Verify OTP to Email API #################################
@app.route('/email_otp_verification', methods=['POST'])
def email_otp_verification():
    try:
        
        

        cursor.execute("SELECT customer_id,email  FROM public.login_details ORDER BY customer_id DESC LIMIT 1" )
        cust_id_all = cursor.fetchone()
        print("EMail:--------",cust_id_all[1])
        email = cust_id_all[1]
#        email = request.json.get('email')
        provided_otp = int(request.json.get('provided_otp'))
        cursor.execute("SELECT email_otp, email_otp_status, email_otp_generated_date_time FROM public.login_details WHERE email = %s", (email,))
        record = cursor.fetchone()
        if not record:
            raise ValueError("Email not registered.")
        
        db_otp, otp_status, otp_generated_date_time= record
        print("otp_status:-----------",otp_status)
        customer_id = session.get('customer_id')
        if otp_status == "SENT":
            current_time = datetime.now()
            difference_in_minutes = (current_time - otp_generated_date_time).total_seconds() / 60
            print("difference_in_minutes:-----------",difference_in_minutes)
            if difference_in_minutes > 10:
                cursor.execute("UPDATE public.login_details SET email_otp_status = 'EXPIRED' WHERE email = %s", (email,))
                conn.commit()
                return jsonify({"status": "error", "message": "OTP is expired. Please re-generate OTP again."}), 400
            else:
                print("db_otp:-------",type(db_otp) , db_otp)
                print("provided_otp:-------",type(provided_otp), provided_otp)
                if provided_otp == db_otp:
                    cursor.execute("UPDATE public.login_details SET email_otp_status = 'SUCCESS' WHERE email = %s", (email,))
                    conn.commit()
                    return jsonify({"status": "success", "message": "OTP verification successful."}), 200
                else:
                    cursor.execute("UPDATE public.login_details SET email_otp_status = 'FAILED' WHERE email = %s", (email,))
                    conn.commit()
                    return jsonify({"status": "error", "message": "Invalid OTP provided."}), 400
        else:
            return jsonify({"status": "error", "message": "Please re-generate OTP again."}), 400

    except ValueError as ve:
        logging.error(f"ValueError: {ve}")
        return jsonify({"status": "error", "message": str(ve)}), 400
    except Exception as e:
        logging.error(f"Exception: {e}")
        return jsonify({"status": "error", "message": "An unexpected error occurred."}), 500
        
############################ API for signup page############################

############################ API for forget/Reset password ############################
@app.route('/change_forgot_password', methods=['POST'])
def change_forgot_password():
    try:
        customer_id = session['customer_id']
        print("customer_id:-----------",customer_id)
        mobile = int(request.json.get("mobile"))
        email = request.json.get("email")
        new_password = request.json.get("new_password")
        confirm_password = request.json.get("confirm_pass")
        print("mobile:------------",type(mobile),mobile)
        print("email:------------",email)
        print("new_password:------------",new_password)
        print("confirm_password:------------",confirm_password)
        if new_password != confirm_password:
            raise ValueError("NewPassword and ConfirmPassword does not match")

        cursor.execute('SELECT email FROM public.login_details WHERE email = %s', (email,))
        account = cursor.fetchone()
        if not account:
            raise ValueError("Invalid mobile number")
        print("account:------------",type(account[0]),account[0])
        db_email = account[0]
        
        cursor.execute('SELECT mobile FROM public.login_details WHERE mobile = %s', (mobile,))
        account1 = cursor.fetchone()
        if not account:
            raise ValueError("Invalid mobile number")
        print("account1:------------",type(account1[0]),account1[0])
        db_mobile = int(account1[0])
        
        if email == db_email:
            if mobile == db_mobile:
                if not new_password:
                    raise ValueError("NewPassword is missing or None.")
                    
                if not is_valid_password(new_password):
                    raise ValueError("Invalid password. Password does not meet policy requirements.")
    
                _hashed_password = generate_password_hash(new_password)
                cursor.execute(
                    "UPDATE public.login_details SET password = %s,encrypted_password = %s WHERE mobile = %s",
                    (_hashed_password,_hashed_password, mobile)
                )
                conn.commit()
                return jsonify({"status": "success", "message": "Password updated successfully!"})
            else:
                raise ValueError("Invalid Mobile")
        else:
            raise ValueError("Invalid Email")

    except ValueError as ve:
        logging.error(f"ValueError: {ve}")
        return jsonify({"status": "error", "message": str(ve)}), 400

    except Exception as e:
        logging.error(f"Exception: {e}")
        return jsonify({"status": "error", "message": "An unexpected error occurred."}), 500


def is_valid_password(password):
    if (
        len(password) < PASSWORD_MIN_LENGTH
        or not any(char.isupper() for char in password)
        or not any(char.isdigit() for char in password)
        or not any(char in "!@#$%^&*()_-+=<>,.?/:;{}[]|\\~" for char in password)
    ):
        return False
    return True

############################ API for new OTP ############################
@app.route('/otp_change_forgot_password', methods=['POST'])
def otp_change_forgot_password():
   email = request.json.get("email")  
   print(email)
   mobile = request.json.get("mobile") 
   print(mobile)
   
   cursor = conn.cursor()
   cursor.execute('SELECT * FROM login_details WHERE mobile = %s', (mobile,))
   print("mobile details")
   account = cursor.fetchone()
   if account:
           otp = randint(100000, 999999)
           cursor = conn.cursor()
           cursor.execute(
               "UPDATE public.login_details "
               "SET new_otp = %s "
               "WHERE mobile = %s and email = %s", 
               (otp, mobile, email)
           )
           conn.commit()        
    
           logging.info(f"OTP sent to mobile number: {mobile}")
           return jsonify({"status": "success", "message": "OTP sent successfully."}), 200
   else:
       return "Invalid mobile number/emailId"

########################### API for save customer details ####################################

@app.route('/save_customer_details', methods=['POST'])
def save_customer_details():
    try:
        data = request.get_json()
        customer_id = data['customer_id']
        pan = data['pan']
        designation = data['designation']
        average_monthly_income  = data['average_monthly_income']
        average_monthly_expense  = data['average_monthly_expense']
        existing_emi  = data['existing_emi']
        emi_amount  = data['emi_amount']
        industry  = data['industry']
        age_of_business  = data['age_of_business']
        type_of_credit  = data['type_of_credit']
        required_credit_amount  = data['required_credit_amount']
        
        insert_query = """
            INSERT INTO customer_details (customer_id, pan, designation, average_monthly_income, average_monthly_expense, existing_emi, emi_amount, industry, age_of_business, type_of_credit, required_credit_amount)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        values = (
            customer_id, pan, designation, average_monthly_income, average_monthly_expense, existing_emi, emi_amount, industry, age_of_business, type_of_credit, required_credit_amount
            )

        cursor.execute(insert_query, values)
        conn.commit()

        response = {"message": "Data saved successfully"}
        return jsonify(response), 200

    except Exception as e:
        error_response = {"error": str(e)}
        return jsonify(error_response), 500



@app.route('/save_customer_details1', methods=['POST'])
def save_customer_details1():

    try:
        data = request.get_json()
        #customer_id = session.get('customer_id')
        #print("customer_id:-----------",customer_id)
        print("EMAIL_FROM_LOGIN:-----------",data['email'])
        
        email = data['email']
        ### Extracting customer_id from email ###
        cursor.execute("SELECT customer_id FROM login_details WHERE email = %s", (email,))
        custo_id = cursor.fetchone()
        print("custo_id:----", custo_id[0])
        customer_id = custo_id[0]
        
        if customer_id is None:
            return jsonify({"error": "Customer ID not found in session"}), 400
        
        app.logger.debug(f"customer_id: {customer_id}")
       # customer_id = data['customer_id']
        pan = data['pan']
        occupation = data['occupation']
        monthly_income  = data['monthly_income']
        print("customer_id:----" ,customer_id)
        print("pan:----" ,pan)
        print("occupation:----" ,occupation)
        print("monthly_income:----" ,monthly_income)
        monthly_expenses  = data['monthly_expenses']
        print("monthly_expenses:----" ,monthly_expenses)
        
      
        insert_query = """
            INSERT INTO public.customer_details(customer_id, pan, designation, average_monthly_income, average_monthly_expense)
            VALUES (%s, %s, %s, %s, %s)
        """
        values = (customer_id, pan, occupation, monthly_income,123)

        cursor.execute(insert_query, values)
        conn.commit()

        response = {"message": "Data saved successfully"}
        
        return jsonify(response), 200

    except Exception as e:
        logging.error(f"Exception: {e}")
        conn.rollback()  # Rollback changes to the database
        error_response = {"error": str(e)}
        return jsonify(error_response), 500

#**********************************************************
@app.route('/save_customer_details22', methods=['POST'])
def save_customer_details2():
    #try:
        data = request.get_json()
        email1 = data['email']
        print("email1:---------",email1)
        try:
            email = email1["email"]
        except Exception as e:
            print("in save_custmr_1:-----",e)
            email = email1
        print("email:-----------",email)
        ### Extracting customer_id from email ###
        cursor.execute("SELECT customer_id FROM login_details WHERE email = %s", (email,))
        custo_id = cursor.fetchone()
        customer_id = custo_id[0]
        print("customer_id:-----------",customer_id)
        
        existing_emi  = data['existing_emi']
        emi_amount  = data['emi_amount']
        industry  = data['industry']
        age_of_business  = data['age_of_business']
        type_of_credit  = data['type_of_credit']
        required_credit_amount  = data['required_credit_amount']
        
        print("existing_emi:-----",existing_emi)
        print("emi_amount:-----",emi_amount)
        print("industry:-----",industry)
        print("age_of_business:-----",age_of_business)
        print("type_of_credit:-----",type_of_credit)
        print("required_credit_amount:-----",required_credit_amount)
        

        insert_query = """UPDATE customer_details SET existing_emi = %s, emi_amount = %s, industry = %s, age_of_business = %s, type_of_credit = %s, required_credit_amount = %s WHERE customer_id = %s"""
        values = (
             existing_emi, emi_amount, industry, age_of_business, type_of_credit, required_credit_amount,customer_id
            )

        cursor.execute(insert_query, values)
        conn.commit()
	
        neo_score = randint(45, 65)
        #eligible_score = get_eligible_amount(email)
        eligible_score = int(required_credit_amount * (70/100))
        
        insert_query = """UPDATE eligibility_details SET neo_score = %s, eligible_amount = %s WHERE customer_id = %s"""
        values = (
             neo_score, eligible_score ,customer_id
            )

        cursor.execute(insert_query, values)
        
        response = {"message": "Data saved successfully","neo_score" : neo_score,"eligible_score" : eligible_score}
        #response = {"message": "Data saved successfully"}
        return jsonify(response), 200



########################### API for pan verification ####################################

@app.route('/pan_verification', methods=['POST'])
def pan_verification():
    mobile = request.json.get('mobile')
    name = request.json.get('name')
    pan = request.json.get('pan')
 
    cursor.execute("SELECT * FROM pan_details WHERE id = %s", (pan,))
    pan_data = cursor.fetchone()
    
    if pan_data:
        cursor.execute("SELECT * FROM login_details WHERE mobile = %s AND name = %s", (mobile, name)) 
        login_data = cursor.fetchall()    
        cursor.execute("SELECT * FROM customer_details WHERE PAN = %s", (pan,))
        customer_data = cursor.fetchone()
        
        if login_data and customer_data:
            # Update pan_status to VERIFIED in customer_details table
            cursor.execute("UPDATE customer_details SET pan_status = %s WHERE pan = %s",
                           ('VERIFIED', pan))
            conn.commit()          
            response = {
                'message': 'PAN status updated to VERIFIED'
            }
        else:
            cursor.execute("UPDATE customer_details SET pan_status = %s WHERE PAN = %s",
                               ('UNVERIFIED', pan))
            conn.commit()
            
            response = {
                'message': 'PAN status updated to UNVERIFIED'
            }
    else:
        response = {
            'message': 'PAN number not found',
            'status': 'error'
        }
    
    return jsonify(response)


if __name__ == '__main__':  
    app.run() 
########################### API for save cibil score ####################################
 
@app.route('/generate_and_save_cibil_score', methods=['POST'])
def generate_and_save_cibil_score():
    try:
        customer_id = request.json.get('customer_id')
        cibil_score = request.json.get('cibil_score')
        neo_score = request.json.get('neo_score')
        eligible_amount = request.json.get('eligible_amount')
        
        cibil_score = random.randint(300, 900)
        cursor.execute("SELECT * FROM eligibility_details WHERE customer_id = %s", (customer_id,))
        existing_data = cursor.fetchone()
    
        if existing_data:
            cursor.execute("UPDATE eligibility_details SET cibil_score = %s WHERE customer_id = %s AND neo_score = %s AND eligible_amount = %s", (customer_id, cibil_score, neo_score, eligible_amount))
            conn.commit()        
            response = {
                'message': 'CIBIL score updated successfully.',
                'status': 'success'
            }
        else:
            cursor.execute("INSERT INTO eligibility_details (customer_id, cibil_score, neo_score, eligible_amount) VALUES (%s, %s, %s, %s)", (customer_id, cibil_score, neo_score, eligible_amount))
            conn.commit()    
            response = {
                'message': 'CIBIL score saved successfully.',
                'status': 'success'
            }     
    except Exception as e:
            response = {
                'message': 'An error occurred: ' + str(e),
                'status': 'error'
            }
    
    return jsonify(response)

########################### API for NEO SCORE ####################################
 



########################### API for ELIGIBLE AMOUNT ####################################
################################ Verify OTP to Email API #################################


@app.route('/all_otp_verification', methods=['POST'])
def all_otp_verification1():
    try:
        data = request.json
        mobile = data.get('mobile')
        email = data.get('email')
        provided_otp = data.get('otp')
        provided_email_otp = data.get('provided_otp')

        if mobile:
            return verify_mobile_otp(mobile, provided_otp)
        elif email:
            return verify_email_otp(email, provided_email_otp)
        else:
            raise ValueError("Neither mobile nor email provided in the request.")

    except ValueError as ve:
        logging.error(f"ValueError: {ve}")
        return jsonify({"status": "error", "message": str(ve)}), 400

    except Exception as e:
        logging.error(f"Exception: {e}")
        return jsonify({"status": "error", "message": "An unexpected error occurred."}), 500

def verify_mobile_otp(mobile, provided_otp1):
    try:
        #mobile = request.json.get('mobile')
        provided_otp1 = request.json.get('otp')

        if not mobile or len(str(mobile)) != 10:
            raise ValueError("Invalid mobile number provided.")
        if not provided_otp1 or len(str(provided_otp1)) != 6:
            raise ValueError("Invalid OTP provided.")

        cursor.execute(
            "SELECT otp, otp_status, otp_generated_date_time FROM public.login_details WHERE mobile = %s",
            (mobile,)
        )
        record = cursor.fetchone()
        if not record:
            raise ValueError("Mobile number not found in the database.")

        db_otp, otp_status, otp_generated_date_time = record
        if otp_status == "SENT":
            current_time = datetime.now()
            difference_in_minutes = (current_time - otp_generated_date_time).total_seconds() / 60
            print(difference_in_minutes)
            if difference_in_minutes > 10:
                cursor.execute(
                    "UPDATE public.login_details SET otp_status = 'EXPIRED' WHERE mobile = %s",
                    (mobile,)
                )
                conn.commit()
                return jsonify({"status": "error", "message": "OTP is Expired please re-generate otp again"}), 400
            else:
                if provided_otp1 == db_otp:
                    cursor.execute(
                        "UPDATE public.login_details SET otp_status = 'SUCCESS' WHERE mobile = %s",
                        (mobile,)
                    )
                    conn.commit()
                    return jsonify({"status": "success", "message": "OTP verification SUCCESS"}), 200
                else:
                    cursor.execute(
                        "UPDATE public.login_details SET otp_status = 'FAILED' WHERE mobile = %s",
                        (mobile,)
                    )
                    conn.commit()
                    return jsonify({"status": "error", "message": "Invalid OTP provided."}), 400
        else:
            return jsonify({"status": "error", "message": "OTP is Expired please re-generate otp again"}), 400

    except ValueError as ve:
        logging.error(f"ValueError: {ve}")
        return jsonify({"status": "error", "message": str(ve)}), 400

    except Exception as e:
        logging.error(f"Exception: {e}")
        return jsonify({"status": "error", "message": "An unexpected error occurred."}), 500
        
    return jsonify({"status": "success", "message": "Mobile OTP verification SUCCESS"}), 200

def verify_email_otp(email, provided_email_otp):
    try:
        #email = request.json.get('email')
        #provided_otp = request.json.get('provided_otp')
        cursor.execute("SELECT email_otp, email_otp_status, email_otp_generated_date_time FROM public.login_details WHERE email = %s", (email,))
        record = cursor.fetchone()
        if not record:
            raise ValueError("Email not registered.")
        
        db_otp, otp_status, otp_generated_date_time = record
        
        if otp_status == "SENT":
            current_time = datetime.now()
            difference_in_minutes = (current_time - otp_generated_date_time).total_seconds() / 60

            if difference_in_minutes > 10:
                cursor.execute("UPDATE public.login_details SET email_otp_status = 'EXPIRED' WHERE email = %s", (email,))
                conn.commit()
                return jsonify({"status": "error", "message": "OTP is expired. Please re-generate OTP again."}), 400
            else:
                if provided_email_otp == db_otp:
                    cursor.execute("UPDATE public.login_details SET email_otp_status = 'SUCCESS' WHERE email = %s", (email,))
                    conn.commit()
                    return jsonify({"status": "success", "message": "OTP verification successful."}), 200
                else:
                    cursor.execute("UPDATE public.login_details SET email_otp_status = 'FAILED' WHERE email = %s", (email,))
                    conn.commit()
                    return jsonify({"status": "error", "message": "Invalid OTP provided."}), 400
        else:
            return jsonify({"status": "error", "message": "Please re-generate OTP again."}), 400

    except ValueError as ve:
        logging.error(f"ValueError: {ve}")
        return jsonify({"status": "error", "message": str(ve)}), 400
    except Exception as e:
        logging.error(f"Exception: {e}")
        return jsonify({"status": "error", "message": "An unexpected error occurred."}), 500
        
    return jsonify({"status": "success", "message": "Email OTP verification successful."}), 200

pdfkit_options = {
    'page-size': 'A4',
    'margin-top': '0mm',
    'margin-right': '0mm',
    'margin-bottom': '0mm',
    'margin-left': '0mm',
}


#pdfkit_config = pdfkit.configuration(wkhtmltopdf='C:/Program Files/wkhtmltopdf/bin/wkhtmltopdf.exe')
env = Environment(loader=FileSystemLoader('.'))
neo_report_template = env.get_template('neo_report.html')

@app.route('/generate_pdf', methods=['GET'])
def generate_pdf():
    
    data = request.get_json()
    email = data['email']
    cursor = conn.cursor()
    
    cursor.execute("SELECT customer_id FROM login_details WHERE email = %s", (email,))
    custo_id = cursor.fetchone()
    customer_id = custo_id[0]
    print("customer_id:-----------",customer_id)
    
    
    cursor.execute("""
        SELECT ld.customer_id, ld.name, ld.email, ld.mobile,
               cd.pan, cd.designation, cd.average_monthly_income, cd.average_monthly_expense, cd.existing_emi, cd.emi_amount,
               cd.industry, cd.age_of_business, cd.type_of_credit, cd.required_credit_amount,
               ed.eligible_amount, ed.neo_score
        FROM login_details ld
        JOIN customer_details cd ON ld.customer_id = cd.customer_id
        JOIN eligibility_details ed ON ld.customer_id = ed.customer_id
        WHERE ld.customer_id = %s;
    """, (customer_id,))
    
    data = cursor.fetchone()
    
    if not data:
        return jsonify({'error': 'Customer ID not found'}), 404
    
    # Generate a PDF report using the retrieved data
    html_content = """
    <html>
    <head>
        <title>Customer NEO Report</title>
    </head>
    <body>
        <h1>NEO Credit Assesment Report</h1>
        <p><strong>Customer ID :</strong> {}</p>
        <p><strong>Name :</strong> {}</p>
        <p><strong>Email :</strong> {}</p>
        <p><strong>Mobile :</strong> {}</p>
        <p><strong>PAN :</strong> {}</p>
        <p><strong>Designation :</strong> {}</p>
        <p><strong>Average Monthly Income :</strong> {}</p>
        <p><strong>Average Monthly Expense :</strong> {}</p>
        <p><strong>Existing EMI :</strong> {}</p>
        <p><strong>EMI Amount :</strong> {}</p>
        <p><strong>Industry :</strong> {}</p>
        <p><strong>Age of Business :</strong> {}</p>
        <p><strong>Type of Credit :</strong> {}</p>
        <p><strong>Required Credit Amount :</strong> {}</p>
        
        <p><strong>Eligible Amount :</strong> {}</p>
        <p><strong>NEO Score :</strong> {}</p>
    </body>
    </html>
    """.format(*data) 
    
    # Parse the HTML content
    soup = BeautifulSoup(html_content, 'html.parser')
    data_dict = {}
    for p in soup.find_all('p'):
        key = p.strong.text.strip()
        value = p.contents[-1].strip()
        data_dict[key] = value
    
    personal_details_keys = [
        'Customer ID :',
        'Name :',
        'Email :',
        'Mobile :',
    ]
    
    other_details_keys = [
        'PAN :',
        'Designation :',
        'Average Monthly Income :',
        'Average Monthly Expense :',
        'Existing EMI :',
        'EMI Amount :',
        'Industry :',
        'Age of Business :',
        'Type of Credit :',
        'Required Credit Amount :',
        'Required Tenure :',
        'Eligible Amount :',
        'NEO Score :',
    ]
    
    personal_details_table = PrettyTable()
    personal_details_table.field_names = []
    
    other_details_table = PrettyTable()
    other_details_table.field_names = []
    
    for key in personal_details_keys:
        value = data_dict.get(key, '')
        personal_details_table.add_row([key, value])
    personal_details_table.header = False
        
    for key in other_details_keys:
        value = data_dict.get(key, '')
        other_details_table.add_row([key, value])
    other_details_table.header = False
    
    template_data = {
        'personal_details_table': personal_details_table.get_html_string(),
        'other_details_table': other_details_table.get_html_string(),
    }

    rendered_html = neo_report_template.render(data=template_data)   
    pdf_filename = f'NEO_report_{re.sub(r"[^a-zA-Z0-9]", "_", str(customer_id))}.pdf'
    #pdfkit.from_string(rendered_html, pdf_filename, configuration=pdfkit_config, options=pdfkit_options)
    
    return jsonify({'message': 'PDF report generated successfully', 'pdf_filename': pdf_filename}), 200

if __name__ == '__main__':  
    app.run(debug=True) 


