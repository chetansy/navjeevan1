import random
import psycopg2
import psycopg2.extras
import re 
import cgi
form = cgi.FieldStorage()
import urllib.request
import urllib.parse
from flask import Flask, request, session, redirect, url_for, render_template, flash, jsonify,send_file
from flask_mail import Message, Mail
import requests
import psycopg2 
import psycopg2.extras
import re 
from werkzeug.security import generate_password_hash, check_password_hash
import os
from flask_mail import *  
import smtplib
from random import *
import logging  
import datetime
from datetime import datetime,timedelta
import json
import pandas as pd
import pickle
from sklearn.preprocessing import OneHotEncoder, MinMaxScaler
import pickle
import joblib
from io import BytesIO
import pickletools
import urllib.request
import urllib.parse
from flask_mail import *

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestRegressor, GradientBoostingRegressor
from sklearn.metrics import mean_squared_error

import pdfkit
from jinja2 import Environment, FileSystemLoader
from prettytable import PrettyTable
from bs4 import BeautifulSoup


##====================== Importing from other files  ================================##
from apis.global_functions import sendSMS , get_neo_score, get_eligible_amount , mobile_sendotp, email_sendotp1 , signup_with_credentials ,email_exists
from apis.global_functions import mobile_exists, is_valid_password


app = Flask(__name__)
mail = Mail(app)

app.config["SECRET_KEY"] = 'root'
app.config["MAIL_SERVER"]='smtpout.secureserver.net'
app.config["MAIL_USE_TLS"] = True      
app.config["MAIL_PORT"] = 587      
app.config["MAIL_USERNAME"] = 'pallavi.uike@creditsiddhi@.com'  
app.config['MAIL_PASSWORD'] = 's'  

#app.secret_key = 'root'
logging.basicConfig(level=logging.INFO)


app.config['SESSION_TYPE'] = 'filesystem'

#### Online Databse configuration details
DB_HOST = "dpg-ck5a6oeru70s739qi8ug-a"
DB_NAME = "navjeevan_data"
DB_USER = "navjeevan_data_user"
DB_PASS = "263sRonJ5pLLli2OfSN6YzptaWucb2jb"
DB_PORT = "5432"

#DB_HOST = "localhost"
#DB_NAME = "navjeevan_data"
#DB_USER = "postgres"
#DB_PASS = "1234"
#DB_PORT = "5432"

conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST, port=DB_PORT)
conn.autocommit = True
cursor = conn.cursor()
 
# Password policy constants
MAX_LOGIN_ATTEMPTS = 3
PASSWORD_MIN_LENGTH = 8
PASSWORD_EXPIRY_DAYS = 90


smsApiKey = "MmZhOTNmMWQ2MzNmMzI5MDEwNWQ1YjZjMjNmZjgwMDM="
smsSenderId = "CRDSID"
smsApiUrl = "https://api.textlocal.in/send/?"


############################ API for login page############################
@app.route('/login', methods=['POST'])
def login():
	try:
		data = request.get_json()
		
		if data.get('email') is None or data.get('password') is None:
			print({"message": "Email and password cannot be None"})
			return jsonify({"message": "Email and password cannot be None"}), 400
		else:
			email = request.json['email']
			password = request.json['password']
			print("email:----",email)
			#print("password:----------",password)
			
			
			cursor.execute("SELECT password, last_password_change,email_otp_status FROM login_details WHERE email = %s", (email,))
			user_data = cursor.fetchone()
			
			if user_data:
				_hashed_password, last_password_change,email_otp_status = user_data
				print("email_otp_status:------",email_otp_status)
				if email_otp_status != "SUCCESS":
					return jsonify({'message': 'Kindly Verify account before login'}), 500
				
				current_date = datetime.now()
				if last_password_change is None:
					return jsonify({'message': 'Last Password change date not found'}), 500
				
				expiration_date = last_password_change + timedelta(days=PASSWORD_EXPIRY_DAYS)
				if current_date > expiration_date:
					return jsonify({'message': 'Your password has expired. Please change your password.'}), 401
				
				if check_password_hash(_hashed_password, password):
					# Reset login attempts on successful login
					return jsonify({'message': 'Login successful'}), 200
				else:
					# Increment login attempts
					#session['login_attempts'] = session.get('login_attempts', 0) + 1
					# Check if maximum login attempts reached
					#if session['login_attempts'] >= MAX_LOGIN_ATTEMPTS:
					#    return jsonify({'message': 'Maximum login attempts exceeded. Please try again later.'}), 401        
					#else:
					return jsonify({'message': 'Invalid password'}), 401
			else:
				return jsonify({'message':'User not found'}), 404
	
	except Exception as e:
		print("Error in Login:----",e)
		return jsonify({"status": "error", "message": "Please try after some time."})
	


############################ API for signup page############################
@app.route('/signup', methods=['POST'])
def signup():
	try:
		request_data = request.json
		data = request.get_json()
		
		if data.get('email') is None or data.get('mobile') is None or data.get('name') is None or data.get('password') is None:
			print({"message": "Each field need to be filled"})
			return jsonify({"message": "Each field need to be filled"}), 400
		else:
		
			regex = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')  
			
			email = request_data.get('email')
			mobile = request_data.get('mobile')
			password = request_data.get('password')
			
			password_pattern = "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$"
			if re.match(password_pattern, password) is None:                            # Returns None
				return jsonify({"status": "error", "message": "Password should contain At least 1 uppercase ,1 Lowercase, 1 digit, 1 special character"}) 
			if re.fullmatch(regex, email):  
				if mobile and len(str(mobile)) == 10:
					
					# Check if email or mobile already exists in the database
					if email_exists(email):
						return jsonify({"message": "Email already exists"}), 400
					
					if mobile_exists(mobile):
						return jsonify({"message": "Mobile number already exists"}), 400
					
					signup_result = signup_with_credentials(request_data)
					print("signup_result:------------",signup_result['message'])
					if signup_result['message'] == "User signup successfully" :
						#print("Yes:---------")
						if request_data['mobile'] and request_data['email']:
							print("getting mobile:----",request_data['email'])
							#mobile_sendotp(request_data)
							
							#print("getting email:----")
							email_sendotp1(request_data)
						
						return jsonify(signup_result)
				else:
					return jsonify({"status": "error", "message": "Invalid mobile number provided."})
			else:  
				print("The given mail is invalid")  
				return jsonify({"status": "error", "message": "The given mail is invalid."})
		
	except Exception as e:
		print("Error_singup:----",e)
		return jsonify({"status": "error", "message": "Please try after some time."})



	

########################### API for LOGOUT PAGE ####################################
@app.route('/logout/')
def logout():

    print("Logged out successfully!")
    return redirect(url_for('login'))

############################  API for Regenerate Email OTP  ###########################
@app.route('/regenerate_email_otp',methods = ["POST"])
def regenerate_mail_otp():
	
	print("email:----",request.json.get('email'))
	try:
		#email = request.args.get('email')
		data = request.json.get('email')
		
		email1 = data['email']
		print("email1:---------",email1)
		if email1 != {}:
			email = email1
		else:
			email = email1["email"]
		
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
		msg = Message("Email OTP Verification!",
		sender="navjeevan.creditsiddhi@gmail.com",
		recipients=[email])
		
		msg.body = "Your one-time password (OTP) is " + " " + str(email_otp)
		print("getting erorr:--------------------",msg.body)
		mail.send(msg)
		logging.info(f"OTP sent to registered email: {email}")
		print(f"OTP sent to registered email: {email}")
		response_data = {"status": "success", "message": "OTP sent successfully."}
		return response_data
	
	except Exception as e:
		logging.error(f"Exception: {e}")
		response_data = {"status": "error", "message": "Please try after some time."}
		return response_data


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

    except Exception as e:
        logging.error(f"Exception: {e}")
        return jsonify({"status": "error", "message": "Please try after some time."}), 500
        


################################ Verify OTP to Email API #################################
@app.route('/email_otp_verification', methods=['POST'])
def email_otp_verification():
	try:
		#print("data:---------",request.json.get())
		data = request.json.get('email')
		
		email1 = data['email']
		print("email1:---------",email1)
		if email1 != {}:
			email = email1
		else:
			email = email1["email"]
		print("email:---------", type(data), email , data)
		
		provided_otp = int(request.json.get('provided_otp'))
		cursor.execute("SELECT email_otp, email_otp_status, email_otp_generated_date_time FROM public.login_details WHERE email = %s", (email,))
		record = cursor.fetchone()
		if not record:
			#raise ValueError("Email not registered.")
			return jsonify({"status": "error", "message": "Email not registered."}), 400
		
		db_otp, otp_status, otp_generated_date_time= record
		print("otp_status:-----------",otp_status)
		
		if otp_status == "SENT":
			current_time = datetime.now()
			difference_in_minutes = (current_time - otp_generated_date_time).total_seconds() / 60
			print("difference_in_minutes:-----------",difference_in_minutes)
			if difference_in_minutes > 10:
				cursor.execute("UPDATE public.login_details SET email_otp_status = 'EXPIRED' WHERE email = %s", (email,))
				conn.commit()
				return jsonify({"status": "error", "message": "Please re-generate OTP again."}), 400
			else:
				#print("db_otp:-------",type(db_otp) , db_otp)
				#print("provided_otp:-------",type(provided_otp), provided_otp)
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
	
	except Exception as e:
	    logging.error(f"Exception: {e}")
	    return jsonify({"status": "error", "message": "Please try after some time."}), 500
            

############################ API for forget/Reset password ############################
@app.route('/change_forgot_password', methods=['POST'])
def change_forgot_password():
	try:
		request_data = request.get_json()
		data = request.get_json()
		
		if data.get('email') is None or data.get('mobile') is None or data.get('new_password') is None or data.get('confirm_pass') is None:
			print({"message": "Each field need to be filled"})
			return jsonify({"message": "Each field need to be filled"}), 400
		else:
		
			mobile = int(request.json.get("mobile"))
			email = request.json.get("email")
			new_password = request.json.get("new_password")
			confirm_password = request.json.get("confirm_pass")
			#print("mobile:------------",type(mobile),mobile)
			#print("email:------------",email)
			##print("new_password:------------",new_password)
			#print("confirm_password:------------",confirm_password)
			
			password = request_data.get('password')
			
			password_pattern = "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$"
			if re.match(password_pattern, new_password) is None:                            # Returns None
				return jsonify({"status": "error", "message": "Password should contain At least 1 uppercase ,1 Lowercase, 1 digit, 1 special character"}) 	
			cursor.execute("SELECT customer_id FROM login_details WHERE email = %s", (email,))
			data1 = cursor.fetchone()
			print("data:----", data1[0])
			customer_id = data1[0]
			print("customer_id:-----------",customer_id)
			
			
			if new_password != confirm_password:
				#raise ValueError("NewPassword and ConfirmPassword does not match")
				return jsonify({"status": "error", "message": "NewPassword and ConfirmPassword does not match"})
			
			cursor.execute('SELECT email FROM public.login_details WHERE email = %s', (email,))
			account = cursor.fetchone()
			if not account:
				#raise ValueError("Invalid mobile number")
				return jsonify({"status": "error", "message": "Invalid email number."})
			#print("account:------------",type(account[0]),account[0])
			db_email = account[0]
			
			cursor.execute('SELECT mobile FROM public.login_details WHERE mobile = %s', (mobile,))
			account1 = cursor.fetchone()
			if not account1:
				#raise ValueError("Invalid mobile number")
				return jsonify({"status": "error", "message": "Invalid mobile number."})
			print("account1:------------",type(account1[0]),account1[0])
			db_mobile = int(account1[0])
			
			if email == db_email:
				if mobile == db_mobile:
					if not new_password:
						#raise ValueError("NewPassword is missing or None.")
						return jsonify({"status": "error", "message": "NewPassword is missing or None."})
					
					if not is_valid_password(new_password):
						#raise ValueError("Invalid password. Password does not meet policy requirements.")
						return jsonify({"status": "error", "message": "Invalid password. Password does not meet policy requirements."})
					
					_hashed_password = generate_password_hash(new_password)
					cursor.execute(
					"UPDATE public.login_details SET password = %s,encrypted_password = %s WHERE mobile = %s",
					(_hashed_password,_hashed_password, mobile)
					)
					conn.commit()
					return jsonify({"status": "success", "message": "Password updated successfully!"})
				else:
					#raise ValueError("Invalid Mobile")
					return jsonify({"status": "error", "message": "Invalid Mobile Number."})
			else:
				#raise ValueError("Invalid Email")
				return jsonify({"status": "error", "message": "Invalid Email ID."})
	
	
	except Exception as e:
		logging.error(f"Exception: {e}")
		return jsonify({"status": "error", "message": "Please try after some time."}), 500




########################### API for save customer details ####################################

@app.route('/save_customer_details1', methods=['POST'])
def save_customer_details1():
	
	try:
		data = request.get_json()
		
		if data.get('pan') is None or data.get('occupation') is None or data.get('monthly_income') is None or data.get('monthly_expenses') is None:
			print({"message": "Each field need to be filled"})
			return jsonify({"status": "error","message": "Each field need to be filled"}), 400
		else:
		
			print("EMAIL_FROM_LOGIN:-----------",data['email'])
			email = data['email']
			### Extracting customer_id from email ###
			cursor.execute("SELECT customer_id FROM login_details WHERE email = %s", (email,))
			data1 = cursor.fetchone()
			print("data:----", data1[0],type(data1[0]))
			customer_id = data1[0]
			
			if customer_id is None:
				return jsonify({"status": "error","message": "Customer ID not found "}), 400
			
			#app.logger.debug(f"customer_id: {customer_id}")
			pan = data['pan']
			occupation = data['occupation']
			monthly_income  = data['monthly_income']
			monthly_expenses  = data['monthly_expenses']
			pan = pan.upper()
			_hashed_password = generate_password_hash(pan)
			
			print("pan1:----" ,pan1)
			#print("customer_id:----" ,customer_id)
			#print("pan:----" ,pan)
			#print("occupation:----" ,occupation)
			#print("monthly_income:----" ,monthly_income)
			#print("monthly_expenses:----" ,monthly_expenses)
			
			insert_query = """UPDATE public.customer_details SET pan = %s, designation = %s,average_monthly_income = %s,average_monthly_expense = %s WHERE customer_id = %s"""
			values = (
			_hashed_password, occupation ,monthly_income, monthly_expenses,customer_id
			)
			
			cursor.execute(insert_query, values)
			conn.commit()
			
			response = {"status": "success","message": "Data saved successfully"}
			
			return jsonify(response), 200
		
	except Exception as e:
		#logging.error(f"Exception: {e}")
		conn.rollback()  # Rollback changes to the database
		error_response = {"status":"error","message": "Please try after some time."}
		return jsonify(error_response), 500
    

        
        
#**********************************************************
@app.route('/save_customer_details22', methods=['POST'])
def save_customer_details2():
	try:
		data = request.get_json()
		
		if data.get('existing_emi') is None or data.get('emi_amount') is None or data.get('industry') is None or data.get('age_of_business') is None or data.get('type_of_credit') is None or data.get('required_credit_amount') is None :
			print({"message": "Each field need to be filled"})
			return jsonify({"status": "error","message": "Each field need to be filled"}), 400
		else:
			email1 = data['email']
			print("email1:---------",email1)
			
			if email1 != {}:
				email = email1
			else:
				email = email1["email"]
			print("email:-----------",email)
			### Extracting customer_id from email ###
			cursor.execute("SELECT customer_id FROM login_details WHERE email = %s", (email,))
			data1 = cursor.fetchone()
			customer_id = data1[0]
			print("customer_id:-----------",customer_id)
			
			insert_query = """UPDATE customer_details SET existing_emi = %s, emi_amount = %s, industry = %s, age_of_business = %s, type_of_credit = %s, required_credit_amount = %s WHERE customer_id = %s"""
			values = (
			data['existing_emi'], data['emi_amount'], data['industry'], data['age_of_business'], data['type_of_credit'], int(data['required_credit_amount']),customer_id
			)
			
			cursor.execute(insert_query, values)
			conn.commit()
			
			#neo_score = get_neo_score(email)
			#print("neo_score:------------",neo_score)
			#eligible_score = get_eligible_amount(email)
			#print("eligible_score:------------",eligible_score)
			neo_score = randint(45, 65)
			print("neo_score:------------",neo_score)
			
			perc = randint(60, 75)
			print("perc:------------",perc,type(perc))
			eligible_score = int(int(data['required_credit_amount']) * (67/100))
			print("eligible_score:------------",eligible_score,type(eligible_score))
			
			insert_query = """UPDATE eligibility_details SET neo_score = %s, eligible_amount = %s WHERE customer_id = %s"""
			values = (
			neo_score, eligible_score, customer_id
			)
			cursor.execute(insert_query, values)
			
			response = {"status": "success","message": "Data saved successfully","neo_score" : neo_score,"eligible_score" : eligible_score}
			return jsonify(response), 200
	
	except Exception as e:
		#logging.error(f"Exception: {e}")
		error_response = {"status":"error","message": "Please try after some time."}
		return jsonify(error_response), 401


########################### API for pan verification ####################################

@app.route('/pan_verification', methods=['POST'])
def pan_verification():
    
    request_data = request.get_json()
	# Check if required fields are missing
    required_fields = ['mobile', 'name', 'pan']
    for field in required_fields:
        if request_data[field] is None:
            print({"message": "Kindly fill all the Details"})
            return jsonify({"message": "Kindly fill all the Details"}), 400
        else:
            mobile = request.json.get('mobile')
            name = request.json.get('name')
            pan = request.json.get('pan')
         
            cursor.execute("SELECT * FROM customer_details WHERE pan = %s", (pan,))
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

#####################################################################################################
pdfkit_options = {
    'page-size': 'A4',
    'margin-top': '0mm',
    'margin-right': '0mm',
    'margin-bottom': '0mm',
    'margin-left': '0mm',
}

#pdfkit_config = pdfkit.configuration(wkhtmltopdf="C:/Program Files/wkhtmltopdf/bin/wkhtmltopdf.exe")
env = Environment(loader=FileSystemLoader('.'))
neo_report_template = env.get_template('neo_report.html')
#from html2image import Html2Image

@app.route('/generate_pdf', methods=['GET'])
def generate_pdf():
    
	#data = request.get_json()
	required_fields = ["email"]
	for field in required_fields:
		if request.args.get(field) is None:
			print({"message": "Kindly fill all the Details"})
			return jsonify({"message": "Kindly fill all the Details"}), 400
		else:
			email = request.args.get('email')
			cursor = conn.cursor()
			
			cursor.execute("SELECT customer_id FROM login_details WHERE email = %s", (email,))
			data1 = cursor.fetchone()
			customer_id = data1[0]
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
			print("data:-----------",data)
			if not data:
				return jsonify({'error': 'Customer ID not found'}), 404
			
			#hti = Html2Image(output_path= os.getcwd() + "/static/reports/")
			
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
			#print("rendered_html:-----------",rendered_html)
			#pdf_filename = f'NEO_report_{re.sub(r"[^a-zA-Z0-9]", "_", str(customer_id))}.pdf'
			html_filename = f'NEO_report_{re.sub(r"[^a-zA-Z0-9]", "_", str(customer_id))}.html'
			print("html_filename:-----------",html_filename)
			#pdfkit.from_string(rendered_html, html_filename, configuration=pdfkit_config)

			with open("static/reports/" +  html_filename, "w") as f:
				f.write(rendered_html)
			f.close()
			
			#hti.screenshot(html_str=os.getcwd() + "/static/reports/" + html_filename , save_as = "NEO_report_"+f"{str(customer_id)}.jpg")

			url = request.url_root +"static/reports/" +  html_filename
			#url1 = os.getcwd() + "/static/reports/" +  html_filename
			url_new = f"https://github.com/chetansy/navjeevan1/{html_filename}"
			url1 = os.getcwd() + "/static/reports/" + "NEO_report_"+f"{str(customer_id)}.jpg"
			url_new = url1.replace('\\','/')
			print("URL:---------",url_new , type(url_new))
			#return redirect(url)
			#return send_file(url_new)
			return jsonify({'message': 'PDF report generated successfully', 'pdf_filename': str(url_new)}), 200
            

    
@app.route('/get_score', methods=['POST'])
def get_score():
	try:
		data = request.get_json()
		email1 = data['email']
		print("email1:---------",email1)
		if email1 != {}:
			email = email1
		else:
			email = email1["email"]
		print("email:-----------",email)
		### Extracting customer_id from email ###
		cursor.execute("SELECT customer_id FROM login_details WHERE email = %s", (email,))
		data1 = cursor.fetchone()
		customer_id = str(data1[0])
		print("customer_id:-----------",customer_id)
		
		cursor.execute("SELECT neo_score,eligible_amount FROM eligibility_details WHERE customer_id = %s", (customer_id,))
		neo = cursor.fetchone()
		neo_scor = neo[0]
		eligibl_scor = neo[1]
		conn.commit()
		print("neo_score:----",neo_scor)
		return jsonify({"neo_scor": str(neo_scor), "eligibl_scor":str(eligibl_scor)})

	except Exception as e:
		logging.error(f"Exception: {e}")
		error_response = {"status":"error","message": "Please try after some time."}
		return jsonify(error_response), 401
    
    
if __name__ == '__main__':  
    app.run() 
