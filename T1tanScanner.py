from bs4 import BeautifulSoup
from urlparse import urlparse,urljoin
from time import sleep
from datetime import datetime
from requests.auth import HTTPDigestAuth
from posixpath import basename, dirname
import argparse
import requests
import random

# Text formatting for help dialogues
example_text = 'examples:\npython xss_scanner.py http://some.domain.com/\npython xss_scanner.py http://some.domain.com/ -u Some_Username -p "pa$$w0rd!"\npython xss_scanner.py /some/path/to/URL_list -u Some_Username -p "pa$$w0rd!"\n'

# Parser assignment for CLI positional and conditional args
parser = argparse.ArgumentParser(prog="XSS Scanner", description="Spider a given URL and attempt XSS injections on all relevant parameters found.\nAuthentication: Currently only basic auth is supported. Username and Password are not both needed.", epilog=example_text, formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument("URL", type=str, help="input URL")
parser.add_argument("-u","--username", type=str, help="optional username field", default="")
parser.add_argument("-p","--password", type=str, help="optional password field", default="")
parser.add_argument("-l","--linkLimit", type=int, help="once total # of links found == 'linkLimit', spider stops. By default, this is set to 50.", default=20) #set to 20 for testing, will default to 50 for prod
parser.add_argument("--NOSPIDER", help="turn off spider mode. this mode will only inject on paths/parameters given initially (no discovery)", action="store_true")
# arg for changing injection to something other than "T1tanScan"

#parse args
args = parser.parse_args()
urlChecklist = []

def validateURL(url):
	parsedURL = urlparse(url)

	if not bool(parsedURL.scheme):		
		parsedURL = parsedURL._replace(**{"scheme": "http"})
		url = parsedURL.geturl().replace('///', '//')	

	try:		
		response = s.get(url,timeout=10,allow_redirects=False,verify=False) #change timeout to 15 for production
		if response.status_code >= 500:
			print 'Received {} response when attempting to reach {}.'.format(response.status_code, url)		
	except:
		print "Error accessing URL: {}. Please try again.".format(url)
		#print "Exception raised: {}".format(ValueError)
		#print "Response headers as follows: {}".format(response.request.headers)
		url = "" # return empty string to proceed with next item in urlChecklist

	return url	

def getResponse(url):	
	# attempt to connect to url
	try:
		# authenticate to server, if needed
		if authenticated == True:
			auth = s.post(url)
		response = s.get(url)
	
		# TO DO: 
		# Add in support other types of authentication
		
		if response.status_code >= 400:
			print 'Received {} response when attempting to reach {}.'.format(response.status_code, url)
	# throw exception and return empty string
	except:
		print "Error with requested URL: {}.\nContinuing.".format(url)
		return ""	# return empty string to proceed with next item in urlChecklist

	# return response object
	return response.text

def parseResponse(resp,url):
	global discovered

	# delete first item in array
	del urlChecklist[0]

	# parse html with BSoup
	soup = BeautifulSoup(resp, "html.parser")

	# search for all a href values
	""" TODO: add in other searchTerms 'src','content', etc... """
	for link in soup.findAll('a'):
		# parse each URL
		
		# check for path without domain
		if link.get('href')[0] == "/":
			# combine path and domain
			newURL = urljoin(domain,link.get('href'))
			print "newURL = {}".format(newURL)
			# assign domain to newDomain
			newDomain = domain
		else:
			newURL = link.get('href')
			newDomain = parseDomain(newURL)			

		# if the link's domain is different from starting domain, continue
		if newDomain != domain:
			#print "newDomain ({}) does not equal domain ({})".format(newDomain,domain)
			continue

		# seek to beginning of file, read lines, crop out duplicates
		discovered.seek(0)
		lines = discovered.readlines()
		uniqueLines = list(set(lines))
		
		# replace contents of log with unique list
		discovered.seek(0)
		discovered.truncate()
		uniqueList = []

		for line in uniqueLines:
			discovered.write(line)
			uniqueList.append(line.strip())
		
		# if newURL is already in the log, continue		
		if newURL in uniqueList:			
			continue
		
		# else if newURL is already in the array, continue
		elif newURL in urlChecklist:			
			continue
		
		# otherwise, add to log and array
		else:
			discovered.write(newURL)
			discovered.write('\n')
			urlChecklist.append(newURL)

def parseDomain(url):
	# check for protocol
	if (url[0:4] != 'http') and (url[0].isalpha()):
		print "URL does not have a protocol. Adding http as new protocol."
		url = 'http://' + url
	#attempt to parse domain from url
	try:
		parsed_uri = urlparse(url)
		newDomain = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)
	except:
		print "Unable to parse URL: {}. Continuing...".format(url)
		newDomain = ""

	return newDomain

# parses each URL in discovered.log, adds temporary injection parameter to each possible injection point
def parseDiscovered(url, baseDomain):
	# set list to empty
	urlList = []	

	# create temporary injection. will be replaced within injection test function (not yet created)
	sub = "T1tanSc4n"

	# get length of domain
	domainLength = len(baseDomain)
	
	# if domain and url are same length, return url as a list
	if domainLength == len(url):
		urlList.append(url + "?" + sub + "=" + sub)
		urlList.append(url + "#" + sub)
		print "urlList (#pd1): ".format(urlList)
		return urlList
	
	# otherwise....
	parsed = urlparse(url)
	fullPath = parsed.path

	# inject on all folder paths
	pathParts = fullPath.split('/')
	for part in pathParts:
		if part == "":
			continue
		newPath = fullPath.replace(part,sub)
		newURL = urljoin(domain,newPath)
		if sub not in newURL:
			newURL = newURL + "?" + sub + "=" + sub
		urlList.append(newURL)
	
	print "urlList (#pd2): ".format(urlList)

	if parsed.query != "":
		parsedQuery = urlparse(parsed.query)

		if "&" in parsed.query:
			paramValuePairs = parsed.query.split("&")
			for pair in paramValuePairs:
				# split each pair
				splitPair = pair.split('=')
				#pairCopy = pair
				# sub one part of each pair at a time
				for part in splitPair:
					newPair = pair.replace(part,sub)
					newURL = url.replace(pair,newPair)
					urlList.append(newURL)
					# need to add functionality for appending to value after '=' in substring
					# 	can use substring[-1] to check if part[-1] is '='

	print "urlList (#pd3): ".format(urlList)

	if parsed.fragment != "":
		newURL = url.replace(parsed.fragment,sub)
		urlList.append(newURL)
	else:
		newURL = url + "#" + sub
		urlList.append(newURL)

	print "urlList (#pd4): ".format(urlList)

	if "?" in url and "=" in url:
		newURL = url + "&" + sub + "=" + sub
		urlList.append(newURL)
	elif "?" in url:
		newURL = url.replace("?","?"+sub+"="+sub)
		urlList.append(newURL)
	else:
		newURL = url + "?" + sub + "=" + sub
		urlList.append(newURL)

	print "urlList (#pd5): ".format(urlList)

	return urlList

def checkInjections(listOfUrls):
	foundURLs = []
	badURLs = []
	sub = "T1tanSc4n"

	for url in listOfUrls:
		with open('injections.list') as injections:
			lines = injections.readlines()
			for line in lines:
				injection = line.strip()
				newURL = url.replace(sub,injection)
				resp = getResponse(newURL)
				print "URL being tested (newURL): {}".format(newURL)
				#if injection in resp.decode("utf8","ignore"):
				if injection in resp:
					print "found {} in response object".format(injection)
					foundURLs.append(newURL)
					quit()
				else:
					print "{} not found in response object".format(injection)
					badURLs.append(newURL)
				sleep(random.uniform(0.5, 1.5))	# range(0.5, 1.5) second delay between requests
												# (so we don't break servers, and appear a little more human at the same time)

	print "List of URLs with matching injection in response:\n{}".format(foundURLs)

	return foundURLs

# Main:
# set headers
headers = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:52.0) Gecko/20100101 Firefox/52.0',
    'Accept-Encoding': ', '.join(('gzip', 'deflate')),
    'Accept': '*/*',
    'Connection': 'keep-alive',
}

# parse arguments
#logFile = 'discovered-' + str(datetime.now()) + '.log'
logFile = 'discovered.log'
discovered = open(logFile, 'w+')

# create Session object
s = requests.Session()
s.headers = {'User-Agent': 'Mozilla/5.0'}
authenticated = False

# check args for credentials
# included use cases for username-no-password and password-no-username
if args.username != "":
	if args.password != "":
		s.auth = (args.username, args.password)		
	else:
		s.auth = (args.username, "")		
	authenticated = True
elif args.password != "":
	s.auth = ("", args.password)
	authenticated = True
	
# assign starting URL
startingURL = args.URL

# determine if parsed arg is a URL or File
try: # attempts to open file
	potentialFile = open(startingURL, 'r')
	lines = potentialFile.readlines()
	startingURL = lines[0].strip()
	print "startingURL from file is: {}".format(startingURL)
	potentialFile.close()
	
	domain = parseDomain(startingURL)
	print "Primary domain is: {}".format(domain)

	# remove first line, since it will be added back in Main()
	del lines[0]

	if args.NOSPIDER:
		for line in lines:
			discovered.write(line)

except: # if opening of file fails, assumes given arg is a URL
	print "File not found."	
	domain = parseDomain(startingURL)
	print "Primary domain is: {}".format(domain)

# add url from input to log and urlChecklist
urlChecklist.append(startingURL)
discovered.write(startingURL)
discovered.write('\n')

linkLimit = args.linkLimit

# check for nospider flag
if not args.NOSPIDER:
	# begin spider
	while True:
		# if list is emppty, stop spidering
		if len(urlChecklist) == 0:
			break

		print "Checking URL: {}".format(urlChecklist[0])		
		validatedURL = validateURL(urlChecklist[0])
		
		# if URL is invalid, delete and continue
		if validatedURL == "":
			del urlChecklist[0]
			continue

		# get response from URL
		response = getResponse(validatedURL)

		# if response length is non-zero, parse response
		if len(response) > 0:
			parseResponse(response,validatedURL)
		else:
			del urlChecklist[0]
	# Wrap-up:
		# remove duplicates from array
		urlChecklist = list(set(urlChecklist))
		
		# remove anything that has already been checked (using the log file)
		discovered.seek(0)
		lines = discovered.readlines()

		length = len(lines)
		if length > linkLimit:
			break

		for line in lines:
			if line in urlChecklist:
				print "Deleting: {}".format(urlChecklist[urlChecklist.index(line)])
				del urlChecklist[urlChecklist.index(line)]
		
		sleep(random.uniform(0.5, 1.5))	# range(0.5, 1.5) second delay between requests
										# (so we don't break servers, and appear a little more human)

# remove duplicates from log one last time
discovered.seek(0)
lines = discovered.readlines()
lines = list(set(lines))

# re-write to log file without dupes
discovered.seek(0)
for line in lines:
    discovered.write(line)

# set injectedList to empty
injectedList = []

# Begin injection testing:
# add temporary injection into each part of each URL in discovered.log
for line in lines:
	# appends the returned array from parseDiscovered to injectedList
	injectedList.extend(parseDiscovered(line.strip(), domain))

	#remove duplicates
	injectedList = list(set(injectedList))

discovered.close()

print "Full list of URLs to be tested (with injection points):\n{}".format(injectedList)

urlsToTest = checkInjections(injectedList)
urlsToTest = list(set(urlsToTest))

print "Found the following links with injections to be tested further:\n"
for url in urlsToTest:
	print url

'''
-Spider	(DONE)
	-inputURL   	(DONE)
	-validateURL 	(DONE)
	-getResponse	(DONE)
	-parseResponse	(DONE)
	-authentication	(DONE)
-Injector
	-Parse URL list from discovered.log (DONE)
	-injection from file containing XSS injections (IN PROGRESS)
		-Replace 'T1tanXSS' with actual injection
		-getResponse(url) for each URL returned from parsing
		-if injection is found in the response object, add URL to foundList
		-ensure authentication is not broken
	-print foundList to user and quit()
-Resources
	-files for xss
		-line separated injections
		-ensure all "primary" encodings are included for each injection

	# href
	# content
	# src	
'''