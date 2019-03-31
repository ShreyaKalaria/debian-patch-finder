#!/usr/bin/python3

from itertools import islice
import wget
import mechanicalsoup
import os.mkdir
import os.path
from urllib.parse import urljoin, urlsplit


def github_issue_patcher(issue_url):
    global browser
    global patch_links
    browser.open(issue_url[1])
    if browser.get_current_page().find('div', {"class": "gh-header js-details-container Details js-socket-channel js-updatable-content issue"}).find('span', {"class": "State State--red"}) is not None:
        try:
            issue = browser.get_current_page().find_all("div", {"class": "timeline-commits"})
        except TypeError:
            return
        for commit in issue:
            commit_status = commit.find('div', {"class": "commit-ci-status pr-1"})
            greenlit = commit_status.find('summary', {"class": "text-green"})
            if greenlit is None:
                continue
            else:
                patch_link = urljoin(issue_url[1], commit.find('a', {"class": "commit-id"}).get('href'))
                issue_patch = [issue_url[0], patch_link + '.diff']
                patch_links.append(tuple(issue_patch))
    return


def dot_git_patcher(issue_url):
    global browser
    global patch_links
    browser.open(issue_url[1])
    page_links = browser.get_current_page().find_all('a')
    for candidate_link in page_links:
        if candidate_link.text == 'patch':
            patch_link = urljoin(issue_url[1], candidate_link.get('href'))
            issue_patch = [issue_url[0], patch_link]
            patch_links.append(tuple(issue_patch))
        else:
            continue
    return


def gitlab_commit_patcher(commit_url):
    global browser
    global patch_links
    browser.open(commit_url[1])
    if browser.get_current_page().find('a', {"class": "ci-status-icon-success"}) is not None:
        issue_patch = [commit_url[0], commit_url[1] + '.diff']
        patch_links.append(tuple(issue_patch))
    else:
        pass
    return


def bugzilla_patcher(bug_url):
    global browser
    global patch_links
    browser.open(bug_url[1])
    patch_header_candidate = browser.get_current_page().find_all('h2')
    for header in patch_header_candidate:
        if header.text == 'Patches':
            candidate_patch = header.find_next_sibling().find('a')
            try:
                active_patch_check = candidate_patch.text
            except AttributeError:
                continue
            if active_patch_check != 'Add a Patch':
                patch_link = urljoin(browser.get_url(), candidate_patch.get('href'))
                bug_patch = [bug_url[0], patch_link]
                patch_links.append(tuple(bug_patch))
                return
    try:
        attachment_check = browser.get_current_page().find('tr', {"class": "bz_contenttype_text_plain bz_patch"})
    except TypeError:
        return
    if attachment_check is not None:
        patch_link = urljoin(browser.get_url(), attachment_check.find('a').get('href'))
        bug_patch = [bug_url[0], patch_link]
        patch_links.append(tuple(bug_patch))
    return



patch_links = []

if not (os.path.exists('/tmp/patch-finder/')):
    os.mkdir('/tmp/patch-finder/')
    cve_list_file = wget.download(
        'https://salsa.debian.org/security-tracker-team/security-tracker/raw/master/data/CVE/list',
        out='/tmp/patch-finder/cve_list')
else:
    if not (os.path.exists('/tmp/patch-finder/cve_list')):
        cve_list_file = wget.download(
            'https://salsa.debian.org/security-tracker-team/security-tracker/raw/master/data/CVE/list',
            out='/tmp/patch-finder/cve_list')

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
            vulns.append(str(line.split(' ')[0]))

vuln_codes = list(set(vulns))
fixed_from_source = []
browser = mechanicalsoup.StatefulBrowser()
print(len(vuln_codes))
for entry in vuln_codes:
    url = "https://security-tracker.debian.org/tracker/" + entry
    browser.open(url)
    try:
        vuln_status = browser.get_current_page().find_all("table")[1]
    except IndexError:
       # print("No info on package vulnerability status")
        continue
    source = (((vuln_status.select('tr')[1]).select('td')[0]).getText()).replace(" (PTS)", "")
    output = 0
    for row in vuln_status:
        columns = row.select('td')
        parsed_array = []
        for column in columns:
            parsed_array.append(column.text)
        if len(parsed_array) == 4:
                if distribution in parsed_array[1]:
                    '''print("Source package " + source + " (version " + parsed_array[2] + ")" + " is " + parsed_array[3
                    ]+ " (" + entry + ")" + " in " + parsed_array[1])
                    '''
                    if parsed_array[3] == 'fixed':
                        fixed_from_source.append(str(source) + ' - ' + str(parsed_array[2]))
                    else:
                        try:
                            vuln_notes = browser.get_current_page().find('pre')
                            noted_links = vuln_notes.find_all('a')
                        except (TypeError, AttributeError) as errors:
                            continue

                        # print(entry + '\n')
                        for link in noted_links:
                            check_link = urlsplit(link.get('href'))
                            if ('github.com' in check_link[1]) and ('issues' in check_link[2]):
                                sadoo = [entry, link.get('href')]
                                github_issue_patcher(tuple(sadoo))
                            elif ('github.com' in check_link[1]) and ('commit' in check_link[2]):
                                sadoo = [entry, link.get('href') + '.diff']
                                patch_links.append(tuple(sadoo))
                            elif ('gitlab.' in check_link[1]) and ('commit' in check_link[2]):
                                sadoo = [entry, link.get('href')]
                                gitlab_commit_patcher(tuple(sadoo))
                            elif 'git.' in check_link[1][:4]:
                                sadoo = [entry, link.get('href')]
                                dot_git_patcher(tuple(sadoo))
                            elif 'bugs.' in check_link[1][:5]:
                                sadoo = [entry, link.get('href')]
                                bugzilla_patcher(tuple(sadoo))
                            else:
                                pass
                    output = 1

    if output == 0:
       # print("No info on package vulnerability status")
        pass
    # a = input()
browser.close()
patches = list(set(patch_links))
confirm_download = input("Press any key to start downloading")
for patch in patches:
    if patch[1][-6:] == '.patch':
        print(patch[0] + ' - ' + patch[1][-14:])
        wget.download(patch[1], out='/tmp/' + distribution + '_patches - ' + patch[0]+' - ' + patch[1][-14:])
    elif patch[1][-5:] == '.diff':
        print(patch[0] + ' - ' + patch[1][-13:-5] + '.patch')
        wget.download(patch[1], out='/tmp/' + distribution + '_patches - ' + patch[0] + ' - ' + patch[1][-13:-5] + '.patch')
    else:
        print(patch[0] + ' - ' + patch[1][-6:] + '.patch')
        wget.download(patch[1], out='/tmp/' + distribution + '_patches - ' + patch[0]+' - ' + patch[1][-8:] + '.patch')





