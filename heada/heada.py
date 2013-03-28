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
		responseHeaders	= []
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

		# CSP check
		check = heada.checkCsp(responseHeaders)
		if check == False:
			issues.append(CspIssue(service, url, messages))

		# HSTS check
		check = heada.checkHsts(responseHeaders)
		if check == False:
			issues.append(HstsIssue(service, url, messages))

		# XSS check
		check = heada.checkXss(responseHeaders)
		if check == False:
			issues.append(XssIssue(service, url, messages))

		# Content Sniffing check
		check = heada.checkCsniff(responseHeaders)
		if check == False:
			issues.append(CsniffIssue(service, url, messages))

		# Server header check
		# We need to know the value pair, so we pass headers
		check, versions = heada.checkServer(headers)
		if check == False:
			issues.append(ServerIssue(service, url, messages, versions))
		return issues

	# Remove duplicate issues
	def consolidateDuplicateIssues(self, existingIssue, newIssue):
		if (existingIssue.getIssueName() == newIssue.getIssueName()):
			return -1
		return 0


class HeadaCheck():
	cspHeaders		= ['x-webkit-csp', 'x-content-security-policy', 'content-security-policy']
	hstsHeaders		= ['strict-transport-security']
	serverHeaders 	= ['server']
	xpowerHeaders 	= ['x-powered-by', 'x-aspnet-version']
	xssHeaders 		= ['x-xss-protection']
	csniffHeaders 	= ['x-content-type-options']

	def checkCsp(self, headers):
		for header in headers:
			if header.lower() in self.cspHeaders:
				return True
		return False

	def checkHsts(self, headers):
		for header in headers:
			if header.lower() in self.hstsHeaders:
				return True
		return False

	def checkXss(self, headers):
		for header in headers:
			if header.lower() in self.xssHeaders:
				return True
		return False

	def checkCsniff(self, headers):
		for header in headers:
			if header.lower() in self.csniffHeaders:
				return True
		return False

	def checkServer(self, headers):
		banners = []
		for header in headers:
			# If the header is not a name value pair, skip
			# Example would be: HTTP / 200 OK
			if ':' not in header:
				continue
			hdr = header.split(':')[0].strip()
			val = header.split(':', 1)[1].strip()
			lhdr = hdr.lower()
			lval = val.lower()

			if lhdr in self.serverHeaders:
				# Server: Apache is already fixed.
				if lval == 'apache':
					continue
				banners.append((hdr, lval))
			if lhdr in self.xpowerHeaders:
				banners.append((hdr, lval))
		if banners:
			return (False, banners)
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
		return 'Information'

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

class XssIssue(IScanIssue):

	def __init__(self, service, url, httpMessages):
		self.mservice 		= service
		self.murl 			= url
		self.mhttpMessages 	= httpMessages

	def getUrl(self):
		return self.murl

	def getIssueName(self):
		return 'XSS Protection Header Not Enabled'

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
		return 'The response did not contain the x-xss-protection header.'

	def getRemediationDetail(self):
		return 'Some Remediation Detail'

	def getHttpMessages(self):
		return self.mhttpMessages

	def getHttpService(self):
		return self.mservice

class CsniffIssue(IScanIssue):

	def __init__(self, service, url, httpMessages):
		self.mservice 		= service
		self.murl 			= url
		self.mhttpMessages 	= httpMessages

	def getUrl(self):
		return self.murl

	def getIssueName(self):
		return 'Content Sniffing Prevention Header Not Enabled'

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
		return 'The response did not contain the x-content-type-options header.'

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
		# Create string to print
		# i.e. Server: Apache 2
		versions = ''
		for k, v in self.mversion:
			versions += k + ': ' + v + ' '
		return 'The response contained the version header: ' + versions

	def getRemediationDetail(self):
		return 'Some Remediation Detail'

	def getHttpMessages(self):
		return self.mhttpMessages

	def getHttpService(self):
		return self.mservice
