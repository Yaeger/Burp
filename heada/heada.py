# -*- coding: utf-8 -*-
"""
	Name: heada 
	Author: historypeats
"""

from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from java.io import PrintWriter

class BurpExtender(IBurpExtender, IScannerCheck):

	def registerExtenderCallbacks(self, callbacks):

		# Writing streams
		self.stdout = PrintWriter(callbacks.getStdout(), True)
		self.stdout.println('Heada extension loaded.')

		# Keep a reference to our callbacks object
		self.callbacks = callbacks

		# Obtain an extension helpers object
		self.helpers = callbacks.getHelpers()

		# Set our extension name
		callbacks.setExtensionName('heada')

		# Register a custom scanner check
		callbacks.registerScannerCheck(self)

	def doPassiveScan(self, baseRequestResponse):

		# Set vars
		issues 			= []
		responseHeaders = []
		messages 		= [baseRequestResponse]
		response 		= baseRequestResponse.getResponse()
		headers 		= self.helpers.analyzeResponse(response).getHeaders()
		url 			= self.helpers.analyzeRequest(baseRequestResponse).getUrl()
		service 		= baseRequestResponse.getHttpService()
		heada 			= HeadaCheck()
		
		# Extract only the header names
		# headers[] contains a list of name/value header pairs
		for header in headers:
			responseHeaders.append(header.split(':')[0].strip())

		#TODO: The checks are redundant. Clean this up some how.
		# CSP check
		check = heada.checkCsp(responseHeaders)
		if check == False:
			issues.append(CspIssue(service, url, messages))

		# HSTS check
		check = heada.checkHsts(responseHeaders)
		if check == False:
			issues.append(HstsIssue(service, url, messages))

		# Server header check
		# We need to know the value pair, so we pass headers
		check, version = heada.checkServer(headers)
		if check == False:
			issues.append(ServerIssue(service, url, messages, version))
		return issues

	# Remove duplicate issues
	def consolidateDuplicateIssues(self, existingIssue, newIssue):
		if (existingIssue.getIssueName() == newIssue.getIssueName()):
			return -1
		return 0


class HeadaCheck():
	
	cspHeaders	= ['X-WebKit-CSP', 'X-Content-Security-Policy', 'Content-Security-Policy']
	hstsHeaders	= ['Strict-Transport-Security']

	def checkCsp(self, headers):
		for header in headers:
			if header in self.cspHeaders:
				return True
		return False

	def checkHsts(self, headers):
		for header in headers:
			if header in self.hstsHeaders:
				return True
		return False

	def checkServer(self, headers):
		for header in headers:
			if header.split(':')[0].strip() == 'Server':
				# Server: Apache is already fixed.
				if header.split(':')[1].strip() == 'Apache':
					return (True, None)
				return (False, header.split(':')[1].strip())
		return (True, None)

class CspIssue(IScanIssue):

	def __init__(self, service, url, httpMessages):

		self.mservice 		= service
		self.murl 			= url
		self.mhttpMessages 	= httpMessages

	def getUrl(self):
		return self.murl

	def getIssueName(self):
		return 'Content Security Policy (CSP) Not Enabled'

	def getIssueType(self):
		return 0

	def getSeverity(self):
		return 'Low'

	def getConfidence(self):
		return "Certain"

	def getIssueBackground(self):
		return 'Some issue background'

	def getRemediationBackground(self):
		return 'Some Remediation Background'

	def getIssueDetail(self):
		return 'The response did not contain any of the Content Security Policy headers.'

	def getRemediationDetail(self):
		return 'Some Remediation Detail'

	def getHttpMessages(self):
		return self.mhttpMessages

	def getHttpService(self):
		return self.mservice

class HstsIssue(IScanIssue):

	def __init__(self, service, url, httpMessages):

		self.mservice 		= service
		self.murl 			= url
		self.mhttpMessages 	= httpMessages

	def getUrl(self):
		return self.murl

	def getIssueName(self):
		return 'HTTP Strict Transport Security (HSTS) Not Enabled'

	def getIssueType(self):
		return 0

	def getSeverity(self):
		return 'Low'

	def getConfidence(self):
		return "Certain"

	def getIssueBackground(self):
		return 'Some issue background'

	def getRemediationBackground(self):
		return 'Some Remediation Background'

	def getIssueDetail(self):
		return 'The response did not contain the HTTP Strict Transport Security header.'

	def getRemediationDetail(self):
		return 'Some Remediation Detail'

	def getHttpMessages(self):
		return self.mhttpMessages

	def getHttpService(self):
		return self.mservice

class ServerIssue(IScanIssue):

	def __init__(self, service, url, httpMessages, version):

		self.mservice 		= service
		self.murl 			= url
		self.mhttpMessages 	= httpMessages
		self.mversion 		= version

	def getUrl(self):
		return self.murl

	def getIssueName(self):
		return 'Web Server Returns Version In Banner'

	def getIssueType(self):
		return 0

	def getSeverity(self):
		return 'Low'

	def getConfidence(self):
		return "Certain"

	def getIssueBackground(self):
		return 'Some issue background'

	def getRemediationBackground(self):
		return 'Some Remediation Background'

	def getIssueDetail(self):
		return 'The response contained the version header: ' + self.mversion

	def getRemediationDetail(self):
		return 'Some Remediation Detail'

	def getHttpMessages(self):
		return self.mhttpMessages

	def getHttpService(self):
		return self.mservice
