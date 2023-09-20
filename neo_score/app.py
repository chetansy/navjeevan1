# -- coding: utf-8 --
"""
Created on Fri Jul  7 12:19:26 2023

@author: Payal / Aniket
"""

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

from sklearn.preprocessing import OneHotEncoder, MinMaxScaler
import pickle

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestRegressor, GradientBoostingRegressor
from sklearn.metrics import mean_squared_error

import random
from flask_mail import *  
import smtplib
from random import *
import logging  
import datetime
from datetime import datetime
import json

app = Flask(__name__)
mail = Mail(app)

app.config["MAIL_SERVER"]='smtpout.secureserver.net'
app.config["MAIL_PORT"] = 587      
app.config["MAIL_USERNAME"] = 'payal.punde@creditsiddhi.com'  
app.config['MAIL_PASSWORD'] = '*****'  

mail = Mail(app)
app.secret_key = 'root'
logging.basicConfig(level=logging.INFO)

DB_HOST = "localhost"
DB_NAME = "navjeevan_data"
DB_USER = "postgres"
DB_PASS = "1234"
DB_PORT = "5432"

conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST, port=DB_PORT)
conn.autocommit = True
cursor = conn.cursor()
 
########################### API for LOGIN PAGE ####################################
@app.route('/login/', methods=['GET', 'POST'])
def login():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
   
    if request.method == 'POST':
        email = request.json['email']
        print(email)
        password = request.json['password']
        print(password)

        cursor.execute('SELECT * FROM login_details WHERE email = %s', (email,))
        account = cursor.fetchone()
 
        if account:
            pass_word = account['password']
            print(pass_word)
            if check_password_hash(pass_word, password):
                print('Test1')
                session['loggedin'] = True
                session['customer_id'] = account['customer_id']
                session['email'] = account['email']
                print('Login Successful!')
                return redirect(url_for('login'))
            else:
                flash('Incorrect email/password')
        else:
            print('Incorrect email/password2')
            flash('Incorrect email/password')
            
    return render_template('login.html')

########################### API for SIGNUP PAGE #################################### 
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
       print("post method")
    else:
        print("get method")
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    print("hello123 $request")
    name = request.json['name'];
    print("hello")

    email = request.json['email']
    mobile = request.json['mobile']
    password = request.json['password']
    print(name)
    print(email)
    _hashed_password = generate_password_hash(password)
    print("buy")
    
    cursor.execute('SELECT * FROM login_details WHERE name = %s', (name,))
    print("go")
    account = cursor.fetchone()
    print("hi")
    
    try:
        cursor.execute('''INSERT INTO login_details (name, email, mobile, password) VALUES (%s,%s,%s,%s)''', (name, email, mobile, _hashed_password))
        conn.autocommit = True
        conn.commit()
    except Exception as ex:
        print(ex)
    print("Records inserted.....")
    flash('You have successfully signup!')         
    return render_template('signup.html')

########################### API for sendOTP ####################################
@app.route("/sendOTP", methods=['GET','POST'])
def sendSMS(apikey, numbers, sender, message):
    data =  urllib.parse.urlencode({'apikey': apikey, 'numbers': numbers,
        'message' : message, 'sender': sender})
    print(data)
    data = data.encode('utf-8')
    request = urllib.request.Request("https://api.textlocal.in/send/?")
    f = urllib.request.urlopen(request, data)
    fr = f.read()
    return(fr)
'''
resp =  sendSMS('MmZhOTNmMWQ2MzNmMzI5MDEwNWQ1YjZjMjNmZjgwMDM=', '918591741893',
    'Navjeevan', 'OTP number is ')
print (resp)
'''
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
        mobile = request.json.get('mobile')
        provided_otp = request.json.get('otp')

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
@app.route('/email_sendotp',methods = ["GET"])  
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
    msg = Message('OTP',sender = 'payal.punde@creditsiddhi.com', recipients = [email])  
    msg.body = "Your one time password(OTP) is " + " " + str(email_otp)
    mail.send(msg)  
    
    logging.info(f"OTP sent to registerd email: {email}")
    return jsonify({"status": "success", "message": "OTP sent successfully."}), 200

################################ Verify OTP to Email API #################################
@app.route('/email_otp_verification', methods=['POST'])
def email_otp_verification():
    try:
        email = request.json.get('email')
        provided_otp = request.json.get('provided_otp')
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
        
############################ API for forget/Reset password ############################
@app.route('/change_forgot_password', methods=['POST'])
def change_forgot_password():
    try:
        mobile = request.json.get("mobile")
        otp = request.json.get("otp")
        new_password = request.json.get("newPassword")
        confirm_password = request.json.get("confirmPassword")

        if new_password != confirm_password:
            raise ValueError("NewPassword and ConfirmPassword does not match")

        cursor = conn.cursor()
        cursor.execute('SELECT new_otp FROM public.login_details WHERE mobile = %s', (mobile,))
        account = cursor.fetchone()
        if not account:
            raise ValueError("Invalid mobile number")

        db_otp = account[0]  
        if otp == db_otp:
            if not new_password:
                raise ValueError("NewPassword is missing or None.")

            hashed_password = generate_password_hash(new_password)
            cursor.execute(
                "UPDATE public.login_details SET encrypted_password = %s WHERE mobile = %s",
                (hashed_password, mobile)
            )
            conn.commit()
            return jsonify({"status": "success", "message": "Password updated successfully!"})
        else:
            raise ValueError("Invalid OTP")

    except ValueError as ve:
        logging.error(f"ValueError: {ve}")
        return jsonify({"status": "error", "message": str(ve)}), 400

    except Exception as e:
        logging.error(f"Exception: {e}")
        return jsonify({"status": "error", "message": "An unexpected error occurred."}), 500

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
 

@app.route('/neo-score', methods=['POST'])
def get_neo_score():
    customer_id = request.json.get('customer_id')
    print("test0")

    # Query data from the customer_details and eligibility_details tables
    cursor.execute(f'SELECT * FROM customer_details WHERE customer_id = %s', (customer_id,))
    df_customer = pd.DataFrame(cursor.fetchall(), columns=[desc[0] for desc in cursor.description])
    print("test1")
    
    cursor.execute(f'SELECT cibil_score FROM eligibility_details WHERE customer_id = %s', (customer_id,))
    df_eligibility = pd.DataFrame(cursor.fetchall(), columns=['cibil_score'])
    print("test2")

    # Combine the data into a single DataFrame
    df = pd.concat([df_customer, df_eligibility], axis=1)
    #print(df)
    print("test3")

    # Drop unnecessary columns
    df.drop(columns=['customer_id', 'pan', 'pan_status','required_credit_amount'], inplace=True)
    print("test4")
    
   # Loading later
    with open('neo_score_model_and_transformers.pkl', 'rb') as f:
        saved_objects = pickle.load(f)
    
    model = saved_objects['model']
    encoder = saved_objects['encoder']
    scaler = saved_objects['scaler']
        
    # Define the categorical columns
    categorical_columns = ['profession', 'existing_emi', 'type_of_credit', 'industry']

    
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

    return jsonify({'neo_score': neo_score[0]})



########################### API for ELIGIBLE AMOUNT ####################################
 



if __name__ == '__main__':  
    app.run() 

