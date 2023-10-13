import urllib
import psycopg2 
import psycopg2.extras
import pandas as pd
import pickle
from flask import Flask, request, jsonify
from random import randint
from datetime import datetime,timedelta
import logging  
from flask_mail import Message, Mail
from werkzeug.security import generate_password_hash, check_password_hash



# Password policy constants
MAX_LOGIN_ATTEMPTS = 3
PASSWORD_MIN_LENGTH = 8
PASSWORD_EXPIRY_DAYS = 90

app = Flask(__name__)
mail = Mail(app)
smsApiKey = "MmZhOTNmMWQ2MzNmMzI5MDEwNWQ1YjZjMjNmZjgwMDM="
smsSenderId = "CRDSID"
smsApiUrl = "https://api.textlocal.in/send/?"


#DB_HOST = "dpg-ck5a6oeru70s739qi8ug-a"
#DB_NAME = "navjeevan_data"
#DB_USER = "navjeevan_data_user"
#DB_PASS = "263sRonJ5pLLli2OfSN6YzptaWucb2jb"
#DB_PORT = "5432"

DB_HOST = "localhost"
DB_NAME = "navjeevan_data"
DB_USER = "postgres"
DB_PASS = "1234"
DB_PORT = "5432"

conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST, port=DB_PORT)
conn.autocommit = True
cursor = conn.cursor()

def sendSMS(apikey, numbers, sender, message):
    data =  urllib.parse.urlencode({'apikey': apikey, 'numbers': numbers,
        'message' : message, 'sender': sender})
    data = data.encode('utf-8')
    request = urllib.request.Request("https://api.textlocal.in/send/?")
    f = urllib.request.urlopen(request, data)
    fr = f.read()
    return(fr)


def get_neo_score(email):
	#customer_id = request.json.get('customer_id')
	#print("test0")
	print("Email:-----------",email)
	cursor.execute("SELECT customer_id FROM login_details WHERE email = %s", (email,))
	
	data1 = cursor.fetchone()
	print("data:--------------",data1[0])
	customer_id = data1[0]
	# Query data from the customer_details and eligibility_details tables
	cursor.execute('SELECT * FROM customer_details WHERE customer_id = %s', (customer_id,))
	df_customer = pd.DataFrame(cursor.fetchall(), columns=[desc[0] for desc in cursor.description])
	#print("test1")
	
	cursor.execute('SELECT cibil_score FROM eligibility_details WHERE customer_id = %s', (customer_id,))
	df_eligibility = pd.DataFrame(cursor.fetchall(), columns=['cibil_score'])
	#print("test2")
	
	# Combine the data into a single DataFrame
	df = pd.concat([df_customer, df_eligibility], axis=1)
	df.fillna(0,inplace=True)
	print(df)
	#print("test3")
	
	# Drop unnecessary columns
	df.drop(columns=['customer_id', 'pan', 'pan_status','required_credit_amount'], inplace=True)
	#print("test4")
	
	# Loading later
	with open('https://github.com/chetansy/navjeevan1/neo_score_model_and_transformers2.pkl', 'rb') as f:
		saved_objects = pickle.load(f)
	#with open('neo_score_model_and_transformers2.json',"r") as f:
	#	saved_objects = json.load(f)
	#saved_objects = pickle.loads("neo_score_model_and_transformers2.pickle")
	#URI = 'https://github.com/chetansy/navjeevan1/blob/main/neo_score_model_and_transformers2.pkl'
	#saved_objects = joblib.load(BytesIO(requests.get(URI).content))
	#saved_objects = pickle.loads(open("neo_score_model_and_transformers2.pickle", "rb").read())
	#saved_objects = pd.read_pickle("neo_score_model_and_transformers2.pkl")
	#github_raw_url = 'https://github.com/chetansy/navjeevan1/blob/main/neo_score_model_and_transformers2.pkl'
	#response = requests.get(github_raw_url)
	#saved_objects = {}

	#print("saved_project1:============",saved_objects)
	#if response.status_code == 200:
	# Load the pickled data from the response content
	#	saved_objects = pickle.loads(response.content)
	#	print("saved_project2:============",saved_objects)
	model = saved_objects['model']
	encoder = saved_objects['encoder']
	scaler = saved_objects['scaler']
	
	# Define the categorical columns
	categorical_columns = ['designation', 'existing_emi', 'type_of_credit', 'industry']
	#print("categorical_columns:------")
	new_data = df
	
	# Apply one-hot encoding using the same encoder
	#encoder = OneHotEncoder()
	print("one_hot_encoded_new:------",new_data[categorical_columns])
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
	#print("test6")
	
	
	# Apply the model to the DataFrame
	neo_score = model.predict(df)
	
	# Store the output in the eligibility_details table
	cursor.execute(f'UPDATE eligibility_details SET neo_score = %s WHERE customer_id = %s', (neo_score[0], customer_id))
	
	#return jsonify({'neo_score': neo_score[0]})
	return neo_score[0]

def get_eligible_amount(email):
    
    customer_id = request.json.get('customer_id')
    #print("test0")
    
    cursor.execute("SELECT customer_id FROM login_details WHERE email = %s", (email,))
    
    data1 = cursor.fetchone()
    print("data:--------------",data1[0])
    customer_id = data1[0]
    # Query data from the customer_details and eligibility_details tables
    cursor.execute('SELECT * FROM customer_details WHERE customer_id = %s', (customer_id,))
    df_customer = pd.DataFrame(cursor.fetchall(), columns=[desc[0] for desc in cursor.description])
    #print("test1")
    
    cursor.execute('SELECT cibil_score,neo_score FROM eligibility_details WHERE customer_id = %s', (customer_id,))
    df_eligibility = pd.DataFrame(cursor.fetchall(), columns=['cibil_score','neo_score'])
    #print("test2")

    # Combine the data into a single DataFrame
    df = pd.concat([df_customer, df_eligibility], axis=1)
    #print(df)
    #print("test3")

    # Drop unnecessary columns
    df.drop(columns=['customer_id', 'pan', 'pan_status','required_credit_amount'], inplace=True)
    #print("test4")
    
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
    #print("test6")


    # Apply the model to the DataFrame
    eligible_amount = model.predict(df)

    # Store the output in the eligibility_details table
    cursor.execute('UPDATE eligibility_details SET eligible_amount = %s WHERE customer_id = %s', (eligible_amount[0], customer_id))

    #return jsonify({'eligible_amount': eligible_amount[0]})
    return eligible_amount[0]


def mobile_sendotp(data):
    print("mobile:----",data.get('mobile'))
    try:
        mobile = data.get('mobile')
        
        otp = randint(100000, 999999)
        print("OTP:----",otp)
        cursor.execute(
            "UPDATE public.login_details "
            "SET otp = %s, otp_status = 'SENT', otp_generated_date_time = %s "
            "WHERE mobile = %s", 
            (otp, datetime.now(), mobile)
        )
        conn.commit()
        #msg = "Your one-time password (OTP) is " + " " + str(otp)
        msg = f"""Welcome to CreditSiddhi\nUse OTP {str(otp)} to login to your CreditSiddhi account.\nThis is valid for 10 minutes.\nCreditSiddhi personnel do not ask for OTP."""
                
        resp =  sendSMS(smsApiKey, mobile,smsSenderId, msg)
        print("msg from 3rd party apis:-----------",resp)
        logging.info(f"OTP sent to mobile number: {mobile}")
        response_data = {"status": "success", "message": "OTP sent successfully."}
        return response_data

    except Exception as e:
        logging.error(f"Exception: {e}")
        response_data = {"status": "error", "message": "Please try after some time."}
        return response_data



def email_sendotp1(data):
    print("email:----",data.get('email'))
    try:
        email = data.get('email')

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
        msg = Message("Email OTP Verification !",
		  sender="pallavi.uike@creditsiddhi@.com",
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

def signup_with_credentials(data):
    try:
	    # Check if required fields are missing

        name = data.get('name')
        email = data.get('email')
        mobile = data.get('mobile')
        password = data.get('password')
        
        if not is_valid_password(password):
            response_data = {"status": "error", "message": "Invalid password"}
            jsonify(response_data), 400  # Return JSON response with a status code


        _hashed_password = generate_password_hash(password)
        
        try:
            current_date = datetime.now()
            cursor.execute("INSERT INTO login_details (name, email, mobile, password, last_password_change) VALUES (%s, %s, %s, %s, %s)", (name, email.lower(), mobile, _hashed_password, current_date))
            conn.commit()

            response_data = {"message": "User signup successfully"}
            return response_data  # Return JSON response with a status code

        except Exception as e:
            conn.rollback()  
            response_data = {"status": "error", "message": "Please try after some time."}
            return response_data # Return JSON response with a status code

        print("Records inserted.....")

    except Exception as e:
        logging.error(f"Exception: {e}")
        response_data = {"status": "error", "message": "Please try after some time."}
        return response_data

def email_exists(email):
    # Check if email already exists in the database
    cursor.execute("SELECT 1 FROM login_details WHERE email = %s", (email,))
    return cursor.fetchone() is not None

def mobile_exists(mobile):
    # Check if mobile number already exists in the database
    cursor.execute("SELECT 1 FROM login_details WHERE mobile = %s", (mobile,))
    return cursor.fetchone() is not None

def is_valid_password(password):
    if (
        len(password) < PASSWORD_MIN_LENGTH
        or not any(char.isupper() for char in password)
        or not any(char.isdigit() for char in password)
        or not any(char in "!@#$%^&*()_-+=<>,.?/:;{}[]|\\~" for char in password)
    ):
        return False
    return True

