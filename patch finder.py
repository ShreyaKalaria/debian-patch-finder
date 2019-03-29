#!/usr/bin/python3

from itertools import islice
import wget
import mechanicalsoup
import os.path

if not (os.path.exists('/tmp/cve_list')):
    url = "https://salsa.debian.org/security-tracker-team/security-tracker/raw/master/data/CVE/list"
    cve_list_file = wget.download(url, out='/tmp/cve_list')
    cve_list = open(cve_list_file, 'r')
else:
    cve_list = open('/tmp/cve_list', 'r')
reject_entry = ['RESERVED', 'REJECTED', 'NOT-FOR-US', 'TODO']
vulns = []
year_vln = str(input("Enter the CVE year to query(1999-2019):\n"))
distribution = str(input("\nEnter the distribution(jessie to sid:\n"))
query_str = 'CVE-'+year_vln
print("Searching entries matching pattern: " + query_str)
for line in cve_list:
    if line.startswith(query_str):
        check = ''.join(islice(cve_list, 1))
        if all(x not in check for x in reject_entry):
            # print(line.split(' ')[0])
            vulns.append(str(line.split(' ')[0]))
            # print(check)

vuln_codes = list(set(vulns))

browser = mechanicalsoup.StatefulBrowser()
for entry in vuln_codes:
    url = "https://security-tracker.debian.org/tracker/" + entry
    # print(url)
    browser.open(url)
    # browser.launch_browser()
    # print(browser.get_url())
    # browser.get_current_page()
    try:
        vuln_status = browser.get_current_page().find_all("table")[1]
    except TypeError:
        print("No info on package vulnerability status")
        continue

    # print(vuln_status)

    source = (((vuln_status.select('tr')[1]).select('td')[0]).getText()).replace(" (PTS)", "")
    output = 0
    for row in vuln_status:
        columns = row.select('td')
        parsed_array = []
        for column in columns:
            parsed_array.append(column.text)
        if len(parsed_array) == 4:
                if distribution in parsed_array[1]:
                    print("Source package " + source + " (version " + parsed_array[2] + ")" + " is " + parsed_array[3] + " (" + entry + ")" + " in " + parsed_array[1])
                    output = 1

    if output == 0:
        print("No info on package vulnerability status")
    # a = input()





