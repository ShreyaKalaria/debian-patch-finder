#!/usr/bin/python3

from itertools import islice
import wget
import mechanicalsoup
import os
import urllib
from urllib.parse import urljoin, urlsplit
import sys
import argparse
import time
import contextlib
import shutil
from urllib3.exceptions import NewConnectionError, MaxRetryError, ConnectTimeoutError, ConnectionError
from requests.exceptions import RequestException


def try_connection(conn_url):   # Attempt to connect to pages and retry if denied
    global browser
    try:
        browser.open(conn_url)
    except (mechanicalsoup.utils.LinkNotFoundError, NewConnectionError, MaxRetryError, RequestException):  # dead lnk
        return False
    except:  # if denied, wait and retry until successful
        time.sleep(30)
        while True:
            try:
                browser.open(conn_url)
                break
            except:
                time.sleep(30)
                continue
    return True


def github_issue_patcher(issue_url):    # extract the accepted commits from a github issue page
    global browser
    global patch_links
    try_connection(issue_url[2])
    try:
        issue_closed = browser.get_current_page().find('div', {
            "class": "gh-header js-details-container Details js-socket-channel js-updatable-content issue"}).find(
            'span', {"class": "State State--red"})
    except AttributeError:
        return
    if issue_closed is not None:  # if the issue is closed
        try:
            issue = browser.get_current_page().find_all("div", {"class": "timeline-commits"})   # find commits, if any
        except TypeError:
            return
        for commit in issue:
            commit_status = commit.find('div', {"class": "commit-ci-status pr-1"})
            greenlit = commit_status.find('summary', {"class": "text-green"})
            if greenlit is None:    # if commit is accepted to the master branch
                continue
            else:
                patch_link = urljoin(issue_url[2], commit.find('a', {"class": "commit-id"}).get('href'))
                issue_patch = [issue_url[0], issue_url[1], patch_link + '.diff']
                patch_links.append(tuple(issue_patch))
    return


def dot_git_patcher(issue_url):     # extract patch links from pages following the "git.xxxxxx" format
    global browser
    global patch_links
    try_connection(issue_url[2])
    try:
        page_links = browser.get_current_page().find_all('a')   # gather links in page
    except AttributeError:
        return
    for candidate_link in page_links:
        if candidate_link.text == 'patch':  # pretty self-explanatory
            patch_link = urljoin(issue_url[2], candidate_link.get('href'))
            issue_patch = [issue_url[0], issue_url[1], patch_link]
            patch_links.append(tuple(issue_patch))
        else:
            continue
    return


def gitlab_commit_patcher(commit_url):  # check if a gitlab commit is greenlit and if so, extract it
    global browser
    global patch_links
    try_connection(commit_url[2])
    if browser.get_current_page().find('a', {"class": "ci-status-icon-success"}) is not None:   # if greenlit
        issue_patch = [commit_url[0], commit_url[1], commit_url[2] + '.diff']
        patch_links.append(tuple(issue_patch))
    else:
        pass
    return


def bugzilla_patcher(bug_url):     # extract patch links from pages following the "bugs.xxxxxx" format
    global browser
    global patch_links
    try_connection(bug_url[2])
    try:
        patch_header_candidate = browser.get_current_page().find_all('h2')  # search for headers
    except AttributeError:
        return
    for header in patch_header_candidate:
        if header.text == 'Patches':    # if there's a patch header
            candidate_patch = header.find_next_sibling().find('a')  # extract link from patch section
            try:
                active_patch_check = candidate_patch.text
            except AttributeError:
                continue
            if active_patch_check != 'Add a Patch':  # if the patch_link is not empty, extract it
                patch_link = urljoin(browser.get_url(), candidate_patch.get('href'))
                bug_patch = [bug_url[0], bug_url[1], patch_link]
                patch_links.append(tuple(bug_patch))
                return
    try:    # some pages actually post patches in an attachment section, so if not patch section is found, try this
        attachments = browser.get_current_page().find_all('tr', {"class": "bz_contenttype_text_plain bz_patch"})
        attachment_check = attachments[-1]  # get latest attachment
    except (TypeError, AttributeError, IndexError):
        return
    if attachment_check is not None:  # if there is an attachment
        if attachment_check.text == 'Patch':  # if the attachment is actually the patch, extract it
            patch_link = urljoin(browser.get_url(), attachment_check.find('a').get('href'))
            bug_patch = [bug_url[0], bug_url[1], patch_link]
            patch_links.append(tuple(bug_patch))
            return
    return


def download_patches(patches):  # download all extracted patches
    global output_supressor
    downloaded = 0
    print('\n')
    for patch in patches:
        downloaded = downloaded + 1
        print("Progress: {:2.1%}".format(downloaded / int(len(patches))), end="\r")  # Display progress
        if not (os.path.exists('/tmp/patch-finder/patches/' + str(distribution) + '/' + str(year_vln) + '/'
                               + str(patch[0]) + '/')):
            os.mkdir('/tmp/patch-finder/patches/' + str(distribution) + '/' + str(year_vln) + '/'
                     + str(patch[0]) + '/')  # dir for each CVE
        else:   # avoid downloading conflicts
            shutil.rmtree('/tmp/patch-finder/patches/' + str(distribution) + '/' + str(year_vln) + '/'
                          + str(patch[0]) + '/')
            os.mkdir('/tmp/patch-finder/patches/' + str(distribution) + '/' + str(year_vln) + '/'
                     + str(patch[0]) + '/')
        if patch[2][-6:] == '.patch':
            # print('\n' + '/tmp/patch-finder/patches/' + distribution + '/' + str(patch[0]) + '/' + patch[1]
            #       + ' - ' + patch[2][-9:] + '\n')
            try:
                with contextlib.redirect_stdout(output_supressor):  # supress output
                    wget.download(patch[2], out='/tmp/patch-finder/patches/'
                                                + distribution + '/' + str(year_vln) + '/' + str(patch[0]) + '/'
                                                + patch[1] + ' - ' + patch[2][-9:])
            except (ValueError, urllib.error.HTTPError):
                continue
        elif patch[2][-5:] == '.diff':
            # print('\n' + '/tmp/patch-finder/patches/' + distribution + '/' + str(patch[0]) + '/'
            #       + patch[1] + ' - ' + patch[2][-13:-5] + '.patch' + '\n')
            try:
                with contextlib.redirect_stdout(output_supressor):  # supress output
                    wget.download(patch[2], out='/tmp/patch-finder/patches/'
                                                + distribution + '/' + str(year_vln) + '/' + str(patch[0]) + '/'
                                                + patch[1] + ' - ' + patch[2][-8:-5] + '.patch')
            except (ValueError, urllib.error.HTTPError):
                continue
        else:
            # print('\n' + '/tmp/patch-finder/patches/' + distribution + '/' + str(patch[0]) + '/'
            #       + patch[1] + ' - ' + patch[2][-3:] + '.patch' + '\n')
            try:
                with contextlib.redirect_stdout(output_supressor):  # supress output
                    wget.download(patch[2], out='/tmp/patch-finder/patches/'
                                                + distribution + '/' + str(year_vln) + '/' + str(patch[0]) + '/'
                                                + patch[1] + ' - ' + patch[2][-3:] + '.patch')
            except (ValueError, urllib.error.HTTPError):
                continue
    return


def check_directories():    # check if all project directories exist, if not create them
    global output_supressor
    if not (os.path.exists('/tmp/patch-finder/')):
        print('Setting up directory tree at /tmp/patch-finder/ ...')
        os.mkdir('/tmp/patch-finder/')
        print('Downloading the CVE entry list...' + '\n')
        with contextlib.redirect_stdout(output_supressor):  # supress output
            wget.download(
                'https://salsa.debian.org/security-tracker-team/security-tracker/raw/master/data/CVE/list',
                out='/tmp/patch-finder/cve_list')  # get the cve list
        return

    else:
        if not (os.path.exists('/tmp/patch-finder/cve_list')):  # if no cve list is found
            print('Downloading the CVE entry list...' + '\n')
            with contextlib.redirect_stdout(output_supressor):  # supress output
                wget.download(
                    'https://salsa.debian.org/security-tracker-team/security-tracker/raw/master/data/CVE/list',
                    out='/tmp/patch-finder/cve_list')  # get the cve list
        else:   # if the cve list exists, remove it so an updated one can be downloaded
            os.remove('/tmp/patch-finder/cve_list')
            print('Updating the CVE entry list...' + '\n')
            with contextlib.redirect_stdout(output_supressor):  # supress output
                wget.download(
                    'https://salsa.debian.org/security-tracker-team/security-tracker/raw/master/data/CVE/list',
                    out='/tmp/patch-finder/cve_list')  # get the cve list
    return


def query_yes_no(question, default="yes"):  # user input interaction function
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")


output_supressor = open('/tmp/patch-finder-io.txt', 'w')  # supress any wget output
vulnerabilities = []
cve_entries_to_check = []
possible_cve_entries = []

dist_versions = ['jessie', 'stretch', 'buster', 'sid']  # eligible distro versions
cve_yrs = ['1999', '1998', '2000', '2001', '2002', '2003', '2004', '2005', '2006', '2007', '2008', '2009', '2010',
           '2011', '2012', '2013', '2014', '2015', '2016', '2017', '2018', '2019']  # eligible cve years

parser = argparse.ArgumentParser()  # initialize argument parsing

parser.add_argument('-y', '--year', required=True,  # year arguments
                    help='Year of CVE entries to search for')
parser.add_argument('-d', '--distribution', required=True,  # distro version arguments
                    help='Set the distribution to be scanned for vulnerabilities(jessie to sid)')

args = vars(parser.parse_args())  # parse arguments

distribution = args["distribution"]
year_vln = args["year"]

if not any(year in year_vln for year in cve_yrs):  # check input
    print('Bad Input!' + '\n' + 'Enter a valid year(1999-2019).' + '\n')
    exit()
elif not any(version in distribution for version in dist_versions):
    print('Bad Input!' + '\n' + 'Enter a distro version(jessie to sid).' + '\n')
    exit()

check_directories()     # create directory tree if it doesn't exist

if os.path.exists('/tmp/patch-finder/patches/'):
    print('\n' + 'Patch directory found.')
    if query_yes_no('Remove previously downloaded patches?'):
        print('\n' + 'Removing...')
        shutil.rmtree('/tmp/patch-finder/patches/')
        print('Removed!' + '\n')
    else:
        print('Continuing with existing patch directory tree.' + '\n')


cve_list = open('/tmp/patch-finder/cve_list', 'r')

if not (os.path.exists('/tmp/patch-finder/patches/')):  # make patch dir, if it not exists
    os.mkdir('/tmp/patch-finder/patches/')
if not (os.path.exists('/tmp/patch-finder/patches/' + str(distribution) + '/')):  # make distro dir, it it not exists
    os.mkdir('/tmp/patch-finder/patches/' + str(distribution) + '/')
if not (os.path.exists('/tmp/patch-finder/patches/' + str(distribution) + '/' + str(year_vln) + '/')):
    os.mkdir('/tmp/patch-finder/patches/' + str(distribution) + '/' + str(year_vln) + '/')
query_str = 'CVE-'+year_vln  # create search query
print('\n' + 'Searching entries matching pattern ' + '"' + query_str + '"'
      + ' for packages vulnerable in debian ' + str(distribution) + '.')

if not query_yes_no('Continue?'):
    print('Exiting...')
    exit()

reject_entry = ['REJECTED', 'NOT-FOR-US', 'DISPUTED']
recheck_entry = ['RESERVED', 'TODO']

print('\n' + 'Gathering relevant CVE entries...' + '\n')
for line in cve_list:  # check cves
    if line.startswith(query_str):
        check = ''.join(islice(cve_list, 1))
        if all(flag not in check for flag in reject_entry):
            if any(flag in check for flag in recheck_entry):
                possible_cve_entries.append(str(line.split(' ')[0]))
            else:
                cve_entries_to_check.append(str(line.split(' ')[0]))

if len(possible_cve_entries) != 0:  # if an entry is marked as TODO or RESERVED, mark as to-recheck
    future_checks = open('/tmp/patch-finder/pending_checks.txt', 'w')
    for entry in possible_cve_entries:
        future_checks.write(str(entry))
    future_checks.close()

vulnerabilities = list(set(cve_entries_to_check))  # remove duplicate cve entries

fixed_from_source = []  # initialize fixed-from-source package list
not_patched = []
patch_links = []
browser = mechanicalsoup.StatefulBrowser(raise_on_404=True)  # initialize browser
print('\n' + 'There are ' + str(len(vulnerabilities)) + ' relevant CVE entries, patching may take a while....' + '\n')
print('\n' + 'Gathering patches' + '\n')
analyzed_entries = 0
for cve in vulnerabilities:  # for each relevant cve entry
    analyzed_entries = analyzed_entries + 1
    print("Progress: {:2.1%}".format(analyzed_entries / int(len(vulnerabilities))), end="\r")  # Display progress
    url = "https://security-tracker.debian.org/tracker/" + cve  # synthesize corresponding security tracker link
    if not try_connection(url):
        continue
    try:
        vulnerability_status = browser.get_current_page().find_all("table")[1]  # find status table
        package_name = (((vulnerability_status.select('tr')[1]).select('td')[0]).getText()).replace(" (PTS)", "")
    except (IndexError, AttributeError):
        not_patched.append(cve + ' - ' + 'No info found for CVE entry')
        continue
    # package_name = (((vulnerability_status.select('tr')[1]).select('td')[0]).getText()).replace(" (PTS)", "")
    output = 0
    for row in vulnerability_status:  # check rows for distro version
        try:
            columns = row.select('td')
        except AttributeError:
            continue
        status_entry = []
        for column in columns:
            status_entry.append(column.text)
        if len(status_entry) == 4:  # if status row is complete
                if distribution in status_entry[1]:  # if status row matches the distro version
                    if status_entry[3] == 'fixed':  # if package is fixed
                        fixed_from_source.append(str(package_name) + ' - ' + str(status_entry[2]))
                    else:  # else try to find patch links in notes
                        try:
                            entry_notes = browser.get_current_page().find('pre')
                            noted_links = entry_notes.find_all('a')
                        except (TypeError, AttributeError) as errors:
                            continue
                        for link in noted_links:  # attempt to classify patch link based on link content
                            check_link = urlsplit(link.get('href'))  # split url
                            if ('github.com' in check_link[1]) and ('issues' in check_link[2]):  # github issues

                                candidate_details = [cve, str(package_name) + ' - '
                                                     + status_entry[2], link.get('href')]

                                github_issue_patcher(tuple(candidate_details))

                            elif ('github.com' in check_link[1]) and ('commit' in check_link[2]):  # github commits

                                candidate_details = [cve, str(package_name) + ' - '
                                                     + status_entry[2], link.get('href') + '.diff']

                                patch_links.append(tuple(candidate_details))

                            elif ('gitlab.' in check_link[1]) and ('commit' in check_link[2]):  # gitlab commits

                                candidate_details = [cve, str(package_name) + ' - '
                                                     + status_entry[2], link.get('href')]

                                gitlab_commit_patcher(tuple(candidate_details))

                            elif 'git.' in check_link[1][:4]:  # git.xxxx type sites

                                candidate_details = [cve, str(package_name) + ' - '
                                                     + status_entry[2], link.get('href')]

                                dot_git_patcher(tuple(candidate_details))

                            elif 'bugs.' in check_link[1][:5]:  # bugs.xxxxx type sites

                                candidate_details = [cve, str(package_name) + ' - '
                                                     + status_entry[2], link.get('href')]

                                bugzilla_patcher(tuple(candidate_details))

                            elif '.patch' in check_link[2][-6:]:  # raw patches
                                candidate_details = [cve, str(package_name) + ' - '
                                                     + status_entry[2], link.get('href')]
                                patch_links.append(tuple(candidate_details))
                            else:
                                pass
                    output = 1
                else:
                    continue
#    time.sleep(2)  # if the connection gets continuously denied, remove this comment to try to cool down between checks
    if output == 0:
        not_patched.append(package_name + ' - ' + 'No patch found')
        pass

unpatched_packages = list(set(not_patched))  # remove duplicate unpatched entries
unpatched_report = open('/tmp/patch-finder/patches/unpatched_report.txt', 'w')
for entry in unpatched_packages:    # write all unpatched entries to file
    unpatched_report.write(entry + '\n')
unpatched_report.close()

browser.close()
patch_list = list(set(patch_links))  # remove duplicate patches
fixed_packages = list(set(fixed_from_source))
print('\n' + str(len(fixed_packages))
      + ' packages are fixed in source. update your package manager and run upgrades' + '\n')

print("There are " + str(len(patch_list)) + " patches available." + '\n')
if query_yes_no('Download patches?'):
    download_patches(patch_list)
    print('\n' + "Patches successfully downloaded. Check /tmp/patch-finder/patches/ for more details." + '\n')
else:
    os.remove('/tmp/patch-finder/pending_checks.txt')
print('Exiting...' + '\n')
output_supressor.close()
os.remove('/tmp/patch-finder-io.txt')  # clear any leftover output
exit()
