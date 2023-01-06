import requests
import json
from datetime import date
import time
token = ""

url = "https://api.github.com/graphql"

def query_builder(organization , pagination_cursor=None):
		#This will only return 100 vulnerabilities per github repo, could be changed with a double loop
		#Will need to do further analysis on how likely that is
		return """query {
			organization(login: "ORG") {
				repositories(first: 100 , after:AFTER ) {
					nodes {
						name
						vulnerabilityAlerts(first: 100 ) {
							nodes {
								createdAt
								dismissedAt
								dismissReason
								securityVulnerability {
									package {
										name
									}
									severity
									advisory {
										summary
										notificationsPermalink
									}
									vulnerableVersionRange
								}
								vulnerableManifestFilename
								vulnerableManifestPath
								vulnerableRequirements
							}
						}
					}
					pageInfo {
						endCursor
						hasNextPage
					}
				}
			}
}""".replace("AFTER", '"{}"'.format(pagination_cursor) if pagination_cursor else "null").replace("ORG" , organization)

def main():

	orgs = ['X', 'Y']
	headers = {'Authorization': 'bearer ' + str(token)} 
	error_count = 0

	for org in orgs:
			
			#One repo for commure, other hca
			repositories = []
			pagination_cursor = None

			while (True):
				#Query is specific to vuln alerts
				query = query_builder(org , pagination_cursor)
				r = requests.post(url, headers=headers, json={'query': query})
							 
				if r.status_code == 200:
						#could skip next line, slightly more performant
						reponse_json = r.json()

						#Build list of what we want to output and store
						repositories.append(reponse_json['data']['organization']['repositories']['nodes'])

						#Check if there is anymore data, if there is submit token and keep at it
						if reponse_json['data']['organization']['repositories']['pageInfo']['hasNextPage'] == False:
								break
						else:
								pagination_cursor = reponse_json['data']['organization']['repositories']['pageInfo']['endCursor']
				else:
						#Github api isn't very reliable 
						time.sleep(5)
						error_count += 1
						if error_count > 10:
								print ("Github is returning error code {code} and error message {text}".format(code = r.status_code , text = r.text))
								break
								
			
			pretty = json.dumps(repositories, indent=2)
			with open(str(org) + "-" + str(date.today())+ '.json', 'w') as f:
					f.write(pretty)
					


if __name__ == "__main__":
	main()
