# -*- coding: utf-8 -*-
"""
Created on Thu Aug 17 16:08:03 2023

@author: Aniket
"""



# Importing required libraries
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestRegressor, GradientBoostingRegressor
from sklearn.metrics import mean_squared_error
from sklearn.preprocessing import OneHotEncoder, MinMaxScaler
import pickle
import os

# Reading the CSV file
file_path = r"C:\Users\Admin\Downloads\Navjeevan\document\training_data.csv"
df = pd.read_csv(file_path)

df.drop(columns=['eligible_amount','required_credit_amount'], inplace=True)

# Define the categorical columns
categorical_columns = ['profession', 'existing_emi', 'type_of_credit', 'industry']


# Apply one-hot encoding
encoder = OneHotEncoder()
one_hot_encoded = encoder.fit_transform(df[categorical_columns])
df = df.drop(categorical_columns, axis=1)
df = pd.concat([df, pd.DataFrame(one_hot_encoded.toarray(), columns=encoder.get_feature_names_out(categorical_columns))], axis=1)

# Apply min-max scaling
scaler = MinMaxScaler()
df[df.columns.difference(['neo_score'])] = scaler.fit_transform(df[df.columns.difference(['neo_score'])])


# Store it in dataframe
#df = data_scaled

# Changing the datatype of all columns to int32
#df = df.astype('int32')

# Splitting the dataframe into features and target variable
X = df.drop(columns=['neo_score'])
y = df['neo_score']
print(X)
print(y)
print(df.info())

# Splitting the data into training and testing sets (80% train, 20% test)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Defining the Random Forest Regressor model
#model = RandomForestRegressor(n_estimators=50, max_depth=None, min_samples_split=10, min_samples_leaf=1, random_state=42)
model = GradientBoostingRegressor(n_estimators=50, learning_rate=0.01, max_depth=3, min_samples_split=10, random_state=42)

# Fitting the model to the training data
model.fit(X_train, y_train)

# Making predictions on the testing data
y_pred = model.predict(X_test)

# Calculating the mean squared error
mse = mean_squared_error(y_test, y_pred)
print(f"Mean Squared Error: {mse}")


 # Saving
with open('neo_score_model_and_transformers.pkl', 'wb') as f:
    pickle.dump({'model': model, 'encoder': encoder, 'scaler': scaler}, f)


