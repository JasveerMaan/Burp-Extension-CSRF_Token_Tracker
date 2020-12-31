#Author: Jasveer Singh & Samandeep Singh

from burp import IBurpExtender, IHttpListener, IParameter
import re
import os

class BurpExtender(IBurpExtender, IHttpListener):

	def registerExtenderCallbacks(self, callbacks):
		self.callbacks = callbacks
		self.helpers = callbacks.getHelpers()
		callbacks.registerHttpListener(self)
		callbacks.setExtensionName("CSRF Token Updater_v0.3")

		if os.path.exists('Token.txt'):
			os.remove("Token.txt")
			os.remove("Cookie.txt")
		else:
			pass



	def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):

		if messageIsRequest:
			request = messageInfo.getRequest()
			requestHTTPService = messageInfo.getHttpService();
			requestInfo = self.helpers.analyzeRequest(requestHTTPService,request)
			captured_headers = requestInfo.getHeaders()
			body_offset = requestInfo.getBodyOffset()
			body_bytes = request[body_offset:]		
			Requestbody = self.helpers.bytesToString(body_bytes)
	

			if str("param1") in Requestbody: #Looking for specific thing in request body.
				#Read File to be used for replacement.
				readToken = open("Token.txt", "r")
				ReadingToken = readToken.read()
				readCookie = open("Cookie.txt", "r")
				ReadingCookie = readCookie.read()

				BodyParameters = requestInfo.getParameters()

				for x in BodyParameters:
					if "token" in x.getName():
						newtoken = self.helpers.buildParameter(x.getName(), ReadingToken, IParameter.PARAM_URL)
						break

				for i in BodyParameters:
					if "CSRFToken" in i.getName():
						newcookie = self.helpers.buildParameter(i.getName(), ReadingToken, IParameter.PARAM_COOKIE)
						break

				self.updatedRequest = self.helpers.updateParameter(request, newtoken)
				#print("updated token: " + self.updatedRequest)
				self.updatedRequest = self.helpers.updateParameter(self.updatedRequest, newcookie)
				#print("updated cookie: " + self.updatedRequest)
				messageInfo.setRequest(self.updatedRequest)
				readToken.close()
				readCookie.close()

			else:
				pass

		if not messageIsRequest:
			response = messageInfo.getResponse()
			responseInfo = self.helpers.analyzeResponse(response)
			response_headers = responseInfo.getHeaders()
			res_body_offset = responseInfo.getBodyOffset()
			res_body_bytes = response[res_body_offset:]
			Responsebody = self.helpers.bytesToString(res_body_bytes)


			if str("logout.do?token=") in Responsebody:
				TokenBody = re.findall("\/.+/logout.do\?token=[0-9 a-z]{32}", Responsebody) #Since "logout.do" is everywhere in the response, hence I decided to use this.
				SplitTokenBody = TokenBody[0].split("=")
				FinalToken = SplitTokenBody[1]
				
				StoringToken = open("Token.txt", "w")
				StoringToken.write(FinalToken)
				StoringToken.close()

				ResponseHeader = ''.join(response_headers)
				ResponseCookie = re.findall("requestId=[0-9 A-Z a-z]{10,100};", ResponseHeader)
				SplitResponseCookie = ResponseCookie[0].split("=")
				FinalResponseCookie = SplitResponseCookie[1]
	
				StoringCookie = open("Cookie.txt", "w")
				StoringCookie.write(FinalResponseCookie)
				StoringCookie.close()

			else:
				pass
