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
app.config["MAIL_USERNAME"] = 'chetan0yewale@gmail.com'  
app.config['MAIL_PASSWORD'] = 'kqxd ixvw jjfc tgrx'  


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

##########################################################################
@app.route('/', methods=['POST'])
def index():
	return 'Hello World'


    
if __name__ == '__main__':  
    app.run(debug=True) 


