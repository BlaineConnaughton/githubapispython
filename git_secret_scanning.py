import requests
import json
from datetime import date
import time

token = ""

def main():

	headers = {'Authorization': 'bearer ' + str(token)}
	url = "https://api.github.com/enterprises/commure/secret-scanning/alerts?state=open&per_page=100"
	data_to_return = []

	while True:
		r = requests.get(url, headers=headers)
		
		#the pulled data has the actual secrets, go through and redact 
		for secret in r.json():
			secret['secret'] = "REDACTED"
			#build up a new list of data from the pagination
			data_to_return.append(secret)
		
		#Pagination is handled with a link header that comes back, it has a wierd range of data / structure options     
		links = r.headers.get('Link')
		
		#this variable will be used to track if we can break the loop
		exit_function = True
		
		#there can be multiple links, first, next and before.  Why? who knows
		if links != None:
			for link in links.split(','):
				#if there is a next link, we have more data to collect
				if link.find('next') != -1:
					#data is structured url ; rel = 'positional arguemnt' Want the url piece
					base_url = link.split(';')[0]
					#This trims the preceeding and trailing < > from the link because it's structured like XML because people suck
					url = base_url[1:-1] 
					exit_function = False

		if exit_function == True:
			break
										
	pretty = json.dumps(data_to_return, indent=2)
	with open("SecretScanning-" + str(date.today())+ '.json', 'w') as f:
			f.write(pretty)

if __name__ == "__main__":
	main()