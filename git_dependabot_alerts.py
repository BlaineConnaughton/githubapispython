import requests
import json
from datetime import date
import time

#Auth token
token = ""


#Global variables
url = "https://api.github.com/graphql"
orgs = ['hcapatientkeeper', 'commure']
headers = {'Authorization': 'bearer ' + str(token)} 


def query_builder_repositories(organization , pagination_cursor=None):
	#Build query string to find repositories with vulnerabilities
	return """query {
	  organization(login: "ORG") {
		repositories(first: 100 , after:AFTER ) {
		  nodes {
			name
			vulnerabilityAlerts(first: 1 , states:OPEN) {
				nodes{
					createdAt
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

def query_builder_vulnerabilities(name , owner , pagination_cursor=None):

	return """ query {
	repository(name: "REPOSITORY-NAME", owner: "REPOSITORY-OWNER") {
		vulnerabilityAlerts(first: 100 , states:OPEN , after:AFTER) {
			nodes {
				createdAt
				repository {
					name
				}
				securityVulnerability {
					package {
						name
					}
					severity
					vulnerableVersionRange
				}
			}
			pageInfo {
				endCursor
				hasNextPage
			}
		}
	}
	}""".replace("AFTER", '"{}"'.format(pagination_cursor) if pagination_cursor else "null").replace("REPOSITORY-NAME" , name).replace("REPOSITORY-OWNER" , owner)


def get_vulnerable_repositories():
	repos_with_vulnerabilities = []
	
	for org in orgs:
		pagination_cursor = None
		error_count = 0
		
		while (True):
			#Query is specific pulling all the repositories
			query = query_builder_repositories(org , pagination_cursor)
			r = requests.post(url, headers=headers, json={'query': query})

			if r.status_code == 200:
				#could skip next line, slightly more performant
				reponse_json = r.json()
				#go through repos checking if they have any vuln data, add to list if they do
				for repo in reponse_json['data']['organization']['repositories']['nodes']:
					if len(repo['vulnerabilityAlerts']['nodes']) > 0:
						data_to_store = (org , repo['name'])
						repos_with_vulnerabilities.append(data_to_store)

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

	return repos_with_vulnerabilities
				

def main():
	#Get a list of all the repositories.  Each element has 2 parts, repo name and repo owner
	repositories = get_vulnerable_repositories()
	print(repositories)
	repositories_vulnerabilities = []

	for repo in repositories:
		print(repo)
		repo_owner = repo[0]
		repo_name = repo[1]

		pagination_cursor = None
		error_count = 0

		while (True):
			#Query is specific pulling all the repositories
			query = query_builder_vulnerabilities(repo_name , repo_owner , pagination_cursor)
			r = requests.post(url, headers=headers, json={'query': query})

			if r.status_code == 200:
				#could skip next line, slightly more performant
				reponse_json = r.json()

				#Build list of repository vulnerabilites
				repositories_vulnerabilities.append(reponse_json['data']['repository']['vulnerabilityAlerts']['nodes'])

				#Check if there is anymore data, if there is submit token and keep at it
				if reponse_json['data']['repository']['vulnerabilityAlerts']['pageInfo']['hasNextPage'] == False:
					break
				else:
					pagination_cursor = reponse_json['data']['repository']['vulnerabilityAlerts']['pageInfo']['endCursor']
			else:
				#Github api isn't very reliable 
				time.sleep(5)
				error_count += 1
				if error_count > 10:
					print ("Github is returning error code {code} and error message {text}".format(code = r.status_code , text = r.text))
					break


	pretty = json.dumps(repositories_vulnerabilities, indent=2)
	with open("Dependabotalerts" + "-" + str(date.today())+ '.json', 'w') as f:
		f.write(pretty)

if __name__ == "__main__":
	main()