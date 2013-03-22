#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
	Name: logme
	Author: historypeats
'''


from burp import IBurpExtender
from burp import IHttpRequestResponse
from burp import IHttpService
from burp import ITab
from java.io import PrintWriter
from java.lang import RuntimeException
from javax.swing import JSplitPane
from javax.swing import JPanel
from javax.swing import JLabel
from javax.swing import JButton
from javax.swing import JFileChooser
from java.awt import Button
from java.awt import GridLayout
import os
import re

class BurpExtender(IBurpExtender, IHttpRequestResponse, IHttpService, ITab):
	
	# Implement IBurpExtenderder
	def registerExtenderCallbacks(self, callbacks):
		# Keep a reference to our callbacks object
		self.callbacks = callbacks

		# Obtain an extension helpers object
		self.helpers = callbacks.getHelpers()

		# Exclude Requests
		self.excludext = re.compile('\.(gif|jpg|jpeg|bmp|js|tif|tiff|docx|doc|pdf|png|jif|jfif|svg|swf|ico|css)\s')
		
		# Writing streams
		self.stdout = PrintWriter(callbacks.getStdout(), True)
		self.stderr = PrintWriter(callbacks.getStderr(), True)
		
		# Set our extension name
		callbacks.setExtensionName("logme")

		# Main panel
		self.panel = JPanel()
		#self.panel = JPanel(GridLayout(1,3))

		# Create Labels
		self.labelProxy = JLabel("Proxy", JLabel.CENTER)
		self.labelScanner = JLabel("Scanner", JLabel.CENTER)

		# Create buttons
		self.buttonFile = Button("File", actionPerformed=self.selectFile)
		self.buttonSave = Button("Save", actionPerformed=self.save)

		# Add labels and buttons to pane.
		# Order matters for GridLayout
		self.panel.add(self.labelProxy)
		self.panel.add(self.buttonFile)
		self.panel.add(self.buttonSave)
		#self.panel.add(self.labelScanner)
		

		# Add panel to Burps UI
		callbacks.customizeUiComponent(self.panel)
		
		# Add tab to Burp
		callbacks.addSuiteTab(self)
	
	# Set title for our tab
	def getTabCaption(self):
		return "logme"

	# Idk what this does, but it's required
	def getUiComponent(self):
		return self.panel
	
	def selectFile(self, event):
		'''
		Action handler to select a file to save to
		'''
		
		chooser = JFileChooser()
		retVal = chooser.showSaveDialog(None)

		#if reVal == JFileChooser.APPROVE_OPTION:
		self.saveFile = chooser.selectedFile.path
		# Add some kind of exception handler here...

	def save(self, event):
		'''
		Action handler to write logs to file
		'''
		# Todo
		# Add exception handling for files
		self.stdout.println("Writing to file: " + self.saveFile)
		
		# Get file descriptor
		writer = open(self.saveFile, 'w')

		# Get proxy history. Returns IHTTPRequestResponse[]
		proxyHistory = self.callbacks.getProxyHistory()
		
		if proxyHistory:

			# can't get time or IP from burp, so these are fillers
			time = '00:00:00 PM'
			ip = '[127.0.0.1]'

			for item in proxyHistory:
				request = item.getRequest()
				response = item.getResponse()
				service = item.getHttpService()
				protocol = item.getProtocol()
				domain = protocol + "://" + service.getHost()

				try:
					# Write request
					writer.write('======================================================\n')
					writer.write(time + " " + domain + " " + ip + "\n")
					writer.write('======================================================\n')
					writer.write(convString(request) + "\n")	
					
					# If it's an image/flash/css, skip response
					if self.excludext.match(convString(request) + "\n") is None:
						# Write response
						writer.write('======================================================\n')
						writer.write(convString(response) + "\n")
						writer.write('======================================================\n')
						writer.write("\n\n\n")
				except Exception, e:
					# Catch any byte to utf-8 char conversion errors
					self.stderr.println("Error writing to log.")
					continue

		else:
			self.stderr.println("Proxy history empty!")
		
		self.stdout.println("Done writing logs!")
		writer.close()


def convString(byteArray):
	'''
	Converts byte array to string (utf-8) and returns it.
	'''
	return "".join(map(unichr, byteArray)).strip()