import os 
'''provides functions for interacting with the operating system
comes under python's standard utility modules
provides a portable way of using operating system dependent functionality
includes many funcitons to interact with the file system'''
import pandas as pd
'''pandas is a software library written for the python programming language for data manipulation and analysis
importing pandas library into VS python environment referencing it by its alias pd'''
import numpy as np
'''numerical python is an open source python library used for working with arrays
it also has functions for working in the domain of linear algebra, fourier transformation and matrices'''
import matplotlib.pyplot as plt
'''matplotlib is a plotting library for creating static, animated, and interactive visualizations in Python
pylot is a matplotlib module which provides MATLAB like interface'''
import seaborn as sns
'''Seaborn is a library for making statistical graphics in python. It builds on top of matplotlib and integrates closely with pandas data structure
This means that seaborn uses matplotlib as a foundation, and provides additional functionality on top of it. In other words, seaborn is a layer
on top of matplotlib that makes it easier to create certain types of plots, including heatmaps. Because seaborn is built on top of matplotlib,
 it can use all of the functionality of matplotlib, and can also be used to customize the appearance of the plots it creates.'''
import time # provides various time related functions



# Reading the first file containing the list of features
with open("C:\Backup\Backup\Coding\Files\KDDCup199\\kddcupWithTargetFeature.NAMES",'r') as f:
      print(f.read())
'''the "kddcup.names" file and "kddcupWithTargetFeature.NAMES" contains the list of attack types in the first two line and the list of connection features in the following lines by deafult but after editing
it now just has the list of features '''



cols ="""duration,
protocol_type,
service,
flag,
src_bytes,
dst_bytes,
land,
wrong_fragment,
urgent,
hot,
num_failed_logins,
logged_in,
num_compromised,
root_shell,
su_attempted,
num_root,
num_file_creations,
num_shells,
num_access_files,
num_outbound_cmds,
is_host_login,
is_guest_login,
count,
srv_count,
serror_rate,
srv_serror_rate,
rerror_rate,
srv_rerror_rate,
same_srv_rate,
diff_srv_rate,
srv_diff_host_rate,
dst_host_count,
dst_host_srv_count,
dst_host_same_srv_rate,
dst_host_diff_srv_rate,
dst_host_same_src_port_rate,
dst_host_srv_diff_host_rate,
dst_host_serror_rate,
dst_host_srv_serror_rate,
dst_host_rerror_rate,
dst_host_srv_rerror_rate,
"""
# Taking the list of featues into a string literal and then appending it into a python list
# cols is a string literal. literals are a notation for representing a fixed value in a source code



# herein we are appending columns to the dataset and adding a new column name 'target' to the dataset
columns=[] 
# python list. A python list is like a dynamically sized array which contains a collection of things enclosed within [] and separated by commas
for c in cols.split(','):
     if(c.strip()):
        columns.append(c.strip())
#split function splits the given string into a list of strings after breaking the current string by specified separator
#the default separator for split function is a white space
#strip function returns a copy of the string with both leading and trailing characters removed based on the string argument passed as a parameter
#in the function. If no argument is passed then it removes the leading and trailing whitespaces
columns.append('target')
print(len(columns))
# The problem of the missing feature name 'target' corresponding to the 42nd value per row of the second file would have also
#  been solved by directly adding the feature to the cols string literal
# We received "Duplicate names not found error because we already appended target feature name in string literal and additional append of it in the above statement 
# caused duplicacy and names array should not contain duplicate values"



#Finally loading the columns and the corresponding data into the dataframe
path="C:\Backup\Backup\Coding\Files\KDDCup199\kddcup.data_10_percent.gz\\kddcup.data_10_percent_corrected"
df = pd.read_csv(path,names=columns)



with open("C:\Backup\Backup\Coding\Files\KDDCup199\\training_attack_types",'r') as f:
      print(f.read())
# training_attack_types contains a list of intrusion types
#Creaing a dictionary of attack types and classifying them into four categories
'''dos or denial of service is a security threat that occurs when an atacker makes it impossible for legitimate users to access computer systems,
network, services or other information technology resources. Attackers in these types of attacks typically flood web servers, system or networks
with  traffic that overwhelms the victim's resources and makes it difficult or impossible for anyone else to access them'''

'''r2l or remote to local is a type of attack that is performed to access a particular network address remotely illegally'''

'''u2r or user to root attack. Herein the attacker tries to get unauthorized access to local superuser(root) priviliges. Attacker has local access
to the victim machine and tries to gain super user priviliges by exploiting the vulnerabilities in the system'''

'''herein the attacker tries to gain information about the target host. The attacker tries to gather information about the structure
of the web application(pages, parameters, etc) and the supporting infrastructure(operating system, databases, etc'''
attacks_types = {
    'normal': 'normal',
'back': 'dos',
'buffer_overflow': 'u2r',
'ftp_write': 'r2l',
'guess_passwd': 'r2l',
'imap': 'r2l',
'ipsweep': 'probe',
'land': 'dos',
'loadmodule': 'u2r',
'multihop': 'r2l',
'neptune': 'dos',
'nmap': 'probe',
'perl': 'u2r',
'phf': 'r2l',
'pod': 'dos',
'portsweep': 'probe',
'rootkit': 'u2r',
'satan': 'probe',
'smurf': 'dos',
'spy': 'r2l',
'teardrop': 'dos',
'warezclient': 'r2l',
'warezmaster': 'r2l',
}
print(df)
df['Attack Type'] = df.target.apply(lambda r:attacks_types[r[:-1]])
# Integrating Attack Type column in the pandas dataframe by applying lambda function on the target column.
# The lambda function takes an argument 'r' which represents a row of the 'target' column and returns the value in the "attack_types dictionary corresponding 
# to the key 'r[:-1]'. The slice 'r[:-1]' removes the last character from the string in 'r' which is nothing but a full stop "



print(df.head())# displays first few rows
print(df.shape) # returns a tuple denoting the number of rows and columns
print(df.isnull().sum()) # df.isnull() returns a dataframe of booleans with same shape as df containing "True" values for cells that are NULL and "False" values for
#cells that are not NULL. Finally sum() function is called on the Boolean dataframe. Sum function by default treats TRUE values as 1 and FALSE values as 0. So it returns
# a python series object with the number of "True" or NUll values in each column of the dataframe



num_cols = df._get_numeric_data().columns # _get_numeric_data() returns a new dataframe containing only numeric columns. The columns attribute of this new dataframe is 
# then accessed which returns an index object containing the labels of the columns. Hence num_cols contains the labels of all numeric columns in the original df
cate_cols = list(set(df.columns)-set(num_cols)) # set function allows us to perform set difference operation and returns a set that contains labels of  unique non 
# numeric columns in the dataframe. Since sets are not ordered collections so making a list out of the resulting set preserves the order.  
print(cate_cols)



# Plotting all categorical features via bar graph 
counts = df['Attack Type'].value_counts()
categories = counts.index
plt.bar(categories, counts)
plt.show()
#value_counts returns a pandas series object with the counts of unique values in a given pandas series. The 'index' attribute of this series return the unique values and 
# the values attribute returns the counts. The 'bar' function is used to plot these counts as bars on the chart, with the categories being used as the x axis and the counts
# as the y-axis. Finally, the show function is used to display the plot
counts = df['flag'].value_counts()
categories = counts.index
plt.bar(categories, counts)
plt.show()
counts = df['service'].value_counts()
categories = counts.index
plt.figure(figsize=(85, 10)) # the figure function is used to set the size of the plot, which is set to a width of 85 and a height of 10
plt.bar(categories, counts)
plt.show()
counts = df['target'].value_counts()
categories = counts.index
plt.figure(figsize=(25, 10))
plt.bar(categories, counts)
plt.show()
counts = df['protocol_type'].value_counts()
categories = counts.index
plt.bar(categories, counts)
plt.show()



print(len(df.columns))
df = df.dropna('columns')# drop columns with NaN # Since there were no columns with Nan values so the length before and after of columns
# remains same
print(len(df.columns))



unique_counts = df.nunique()
# Print the unique value count for each column
before_drop=set(df.columns)
for col, count in unique_counts.items():
    print(f"{col}: {count}")
df = df[[col for col in df if df[col].nunique() > 1]]# keep columns where there are more than 1 unique values
after_drop=set(df.columns)
print(before_drop-after_drop) # the names of the columns which have been dropped
print(len(df.columns)) # clearly two columns with only one unique value have been dropped



before_corr_table=set(df.columns)
corr = df.corr()
print(corr)# the number of columns before plotting the correlation table were 41 but the correlation table contains only 36 rows and columns 
string_columns = df.select_dtypes(include=['object'])
print(string_columns.columns)# Print the column names with string values
print(before_corr_table-set(corr.index))# printing the list of columns missing before and after correlation and they match with the ones
# that contain string values because it is not possible to plot columns containing string values on a heatmap without encoding the string
# values as numerical values
plt.figure(figsize =(15, 11))
sns.heatmap(corr)
plt.show()



# dropping highly correlated values
df.drop('num_root', axis = 1, inplace = True)
# This variable is highly correlated with serror_rate and should be ignored for analysis.
#(Correlation = 0.9983615072725952)
df.drop('srv_serror_rate', axis = 1, inplace = True)
# This variable is highly correlated with rerror_rate and should be ignored for analysis.
#(Correlation = 0.9947309539817937)
df.drop('srv_rerror_rate', axis = 1, inplace = True)
# This variable is highly correlated with srv_serror_rate and should be ignored for analysis.
#(Correlation = 0.9993041091850098)
df.drop('dst_host_srv_serror_rate', axis = 1, inplace = True)
# This variable is highly correlated with rerror_rate and should be ignored for analysis.
#(Correlation = 0.9869947924956001)
df.drop('dst_host_serror_rate', axis = 1, inplace = True)
# This variable is highly correlated with srv_rerror_rate and should be ignored for analysis.
#(Correlation = 0.9821663427308375)
df.drop('dst_host_rerror_rate', axis = 1, inplace = True)
# This variable is highly correlated with rerror_rate and should be ignored for analysis.
#(Correlation = 0.9851995540751249)
df.drop('dst_host_srv_rerror_rate', axis = 1, inplace = True)
# This variable is highly correlated with srv_rerror_rate and should be ignored for analysis.
#(Correlation = 0.9865705438845669)
df.drop('dst_host_same_srv_rate', axis = 1, inplace = True)



# mapping string features like protocol_type and flag to corresponding numerical values and dropping
# irrelevant features like service for analysis 
pmap = {'icmp':0, 'tcp':1, 'udp':2}
df['protocol_type'] = df['protocol_type'].map(pmap)
# flag feature mapping
fmap = {'SF':0, 'S0':1, 'REJ':2, 'RSTR':3, 'RSTO':4, 'SH':5, 'S1':6, 'S2':7, 'RSTOS0':8, 'S3':9, 'OTH':10}
df['flag'] = df['flag'].map(fmap)
df.drop('service', axis = 1, inplace = True)


 



#STEP2:DATA MODELLING






from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
# Splitting the dataset
df = df.drop(['target', ], axis = 1)
print(df.shape)
# Target variable and train set
y = df[['Attack Type']]
X = df.drop(['Attack Type', ], axis = 1)
sc = MinMaxScaler()
X = sc.fit_transform(X)
print(X)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.33, random_state = 42)
print(X_train.shape, X_test.shape)
print(y_train.shape, y_test.shape)






# Implementing Gaussian Naive Bayes
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import accuracy_score
clfg = GaussianNB()
start_time = time.time()
clfg.fit(X_train, y_train.values.ravel())
end_time = time.time()
print("Training time: ", end_time-start_time)
start_time = time.time()
y_test_pred = clfg.predict(X_train)
end_time = time.time()
print("Testing time: ", end_time-start_time)
print("Train score is:", clfg.score(X_train, y_train))
print("Test score is:", clfg.score(X_test, y_test))



# Python implementation of Decision Tree
from sklearn.tree import DecisionTreeClassifier
clfd = DecisionTreeClassifier(criterion ="entropy", max_depth = 4)
start_time = time.time()
clfd.fit(X_train, y_train.values.ravel())
end_time = time.time()
print("Training time: ", end_time-start_time)
start_time = time.time()
y_test_pred = clfd.predict(X_train)
end_time = time.time()
print("Testing time: ", end_time-start_time)
print("Train score is:", clfd.score(X_train, y_train))
print("Test score is:", clfd.score(X_test, y_test))



#Python code implementation of Random Forest
from sklearn.ensemble import RandomForestClassifier
clfr = RandomForestClassifier(n_estimators = 30)
start_time = time.time()
clfr.fit(X_train, y_train.values.ravel())
end_time = time.time()
print("Training time: ", end_time-start_time)
start_time = time.time()
y_test_pred = clfr.predict(X_train)
end_time = time.time()
print("Testing time: ", end_time-start_time)
print("Train score is:", clfr.score(X_train, y_train))
print("Test score is:", clfr.score(X_test, y_test))
 


#Python implementation of Support Vector Classifier
from sklearn.svm import SVC
clfs = SVC(gamma = 'scale')
start_time = time.time()
clfs.fit(X_train, y_train.values.ravel())
end_time = time.time()
print("Training time: ", end_time-start_time)
start_time = time.time()
y_test_pred = clfs.predict(X_train)
end_time = time.time()
print("Testing time: ", end_time-start_time)
print("Train score is:", clfs.score(X_train, y_train))
print("Test score is:", clfs.score(X_test, y_test))
 


#Python implementation of Logistic Regression
from sklearn.linear_model import LogisticRegression
clfl = LogisticRegression(max_iter = 1200000)
start_time = time.time()
clfl.fit(X_train, y_train.values.ravel())
end_time = time.time()
print("Training time: ", end_time-start_time)
start_time = time.time()
y_test_pred = clfl.predict(X_train)
end_time = time.time()
print("Testing time: ", end_time-start_time)
print("Train score is:", clfl.score(X_train, y_train))
print("Test score is:", clfl.score(X_test, y_test))
 


#Python implementation of Gradient Descent
from sklearn.ensemble import GradientBoostingClassifier
clfg = GradientBoostingClassifier(random_state = 0)
start_time = time.time()
clfg.fit(X_train, y_train.values.ravel())
end_time = time.time()
print("Training time: ", end_time-start_time)
start_time = time.time()
y_test_pred = clfg.predict(X_train)
end_time = time.time()
print("Testing time: ", end_time-start_time)
print("Train score is:", clfg.score(X_train, y_train))
print("Test score is:", clfg.score(X_test, y_test))



#Analyse the training and testing accuracy of each model via bar graphs
names = ['NB', 'DT', 'RF', 'SVM', 'LR', 'GB']
values = [87.951, 99.058, 99.997, 99.875, 99.352, 99.793]
f = plt.figure(figsize =(15, 3), num = 10)
plt.subplot(131)
plt.bar(names, values)
plt.show()
names = ['NB', 'DT', 'RF', 'SVM', 'LR', 'GB']
values = [87.903, 99.052, 99.969, 99.879, 99.352, 99.771]
f = plt.figure(figsize =(15, 3), num = 10)
plt.subplot(131)
plt.bar(names, values)
plt.show()
names = ['NB', 'DT', 'RF', 'SVM', 'LR', 'GB']
values = [1.11452, 2.44087, 17.08491, 218.26840, 92.94222, 633.229]
f = plt.figure(figsize =(15, 3), num = 10)
plt.subplot(131)
plt.bar(names, values)
plt.show()
names = ['NB', 'DT', 'RF', 'SVM', 'LR', 'GB']
values = [1.54329, 0.14877, 0.199471, 126.50875, 0.09605, 2.95039]
f = plt.figure(figsize =(15, 3), num = 10)
plt.subplot(131)
plt.bar(names, values)
plt.show()
