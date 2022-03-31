# Burp-Extension-CSRF_Token_Tracker

During an assessment, I came accross an application which uses different CSRF "Token" along with "Cookie" on every HTTP request. In order to use features such as Burp Suite Repeater, Intruder and etc, I created this extension to allow me to test efficiently. 

# Scenario
Server:

The application responds with new Cookie and "CSRFToken" after every successful request sent to the server.

Client:

Sends HTTP request with the retrieve (from HTTP Response) Cookie and "CSRFToken" to the server.

In short, the extensions reads the server responds to retrieve value of Cookie and "CSRFToken" and sends request to the server with retreived tokens. This allows me to use Burp Suite Repeater/Scanner/Intruder/etc feature without manually updating the Cookie and "CSRFToken".

# To do:
1. Implement multithreading
2. Update the extension to avoid writing to files and save data in a dictionary or something.
