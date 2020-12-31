# Burp-Extension-CSRF_Token_Tracker

During an assessment, I came accross to an application which changes CSRF "Token" along with "Cookie" per request. In order to use features such as Burp Suite Repeater, Intruder and etc, I created this extension to allow me to test efficiently. 

# Scenario
Server:

Responds with new "token" and "CSRFToken" after every request.

Client:

Sends received "token" and "CSRFToken" to the server. Note: Same token can't be used.



So the extensions reads the server responds and finds value of "token" and "CSRFToken". Then using Burp Repeater, the parameter "token" and "CSRFToken" will be updated. 


# To do:
1. Implement multithreading
2. Update the extension to avoid writing to files and save data in a dictionary or something.
