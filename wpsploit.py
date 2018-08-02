#!/usr/bin/env python

import os
import sys
import re
import json
import tempfile
import shutil
import argparse

# Program modules
from lib.colors import colors
from lib.utils import utils
from lib.rules import rules

BANNER = r"""
 __      ____________  _________       __          __   __
/  \    /  \______   \/   _____/_____ |  |   ____ |__|_/  |__
\   \/\/   /|     ___/\_____  \\____ \|  |  /  _ \|  |_   ___|
 \        / |    |    /        \  |_) |  |_(  (_) )  | |  |
  \__/\  /  |____|   /_______  /   __/|____/\____/|__| |__|
       \/                    \/|__|

Aggressive Code Scanner for WordPress Themes/Plugins
Why aggressive? The results indicate possible vulnerabilities present
in the code, however, you will have to exclude false positives alone

Author: Filippo (b4dnewz) Conti
"""

USAGE = """
command examples:
  wpsploit some-plugin
  wpsploit /some-plugin/class-main.php
  wpsploit /plugins/some-plugin/
  wpsploit https://wordpress.org/plugins/some-plugin/
"""

# Vulnerabilities References
# https://github.com/ethicalhack3r/wordpress_plugin_security_testing_cheat_sheet
class wpsploit(object):
    def __init__(self, args={}):
        self.source = args.source
        self.keep = args.keep
        self.save = args.save

    def main(self):
        result = []
        total = 0
        source = self.source

        try:
            # If valid url download try to download and extract it
            # than run tests to extracted source (always a directory)
            # by default the folder is removed once the tests has completed
            # unless keep options is used in this case will be preserved
            if utils.validateURL(source):
                print("Trying to get repository from url: {}{}{}\n".format(colors.CYAN, source, colors.END))
                match = utils.extractInformations(source)
                if not match:
                    raise Exception("The url {} is not a valid repository".format(source))

                # Get the match groups
                kind = match[0][:-1] if match[0].endswith('s') else match[0]
                name = match[1]

                # If url is not already a zip url
                if not re.search(r'.zip', source):
                    source = utils.buildDownloadUrl(name, kind)

                # Build tmp path and extract repository in it
                tmpPath = self.getArchivePath(name)

                # Download the archive and test the code
                self.downloadAndExtract(source, tmpPath)
                result = self.testDirectory(os.path.join(tmpPath, name))

                # Optionally keep the downloaded archive
                if not self.keep: self.clearPath(tmpPath)

            # If it looks like a system path validate it as directory or file
            # than run tests on it capturing the result into variable
            elif utils.validatePath(source):
                if os.path.isdir(source):
                    result = self.testDirectory(source)
                elif os.path.isfile(source):
                    if not source.endswith('.php'):
                        raise Exception("The file extension is not valid.")
                    res = self.testFile(source)
                    result.append(res)
                else:
                    raise Exception("The path \"{}\" doesn't exist or can't be accessed".format(source))

            # If is a normal string try to see if exists in WordPress website
            # repository than try to download it, extract it to tmp folder
            # run the test to the content capture the results and
            # by default the folder is removed once the tests has completed
            # unless keep options is used in this case will be preserved
            else:
                slug = "{}{}{}".format(colors.CYAN, source, colors.END)
                print("Trying to get repository from slug: {}\n".format(slug))
                if utils.validateWordPressURL(source):
                    tmpPath = self.getArchivePath(source)
                    zipUrl = utils.getDownloadPath(source)
                    self.downloadAndExtract(zipUrl, tmpPath)
                    result = self.testDirectory(os.path.join(tmpPath, source))
                    # Optionally keep the downloaded archive
                    if not self.keep: self.clearPath(tmpPath)
                else:
                    raise Exception("The repository called \"{}\" does not exist".format(slug))

            # Print the final scan report
            self.printReport(result)

            # Output the JSON result
            if self.save:
                filename = '{}.json'.format(utils.randomString())
                print("\nSaving results to JSON file: {}{}{}".format(colors.CYAN, filename, colors.END))
                with open(filename, 'w') as outfile:
                    json.dump(result, outfile, indent=2)

        # Output any execution error
        except Exception as e: print("{}{}{}".format(colors.RED, e, colors.END))

    # Recursively test directory files for rules
    def testDirectory(self, path):
        print("Scanning directory: {}".format(path))
        results = []
        files = utils.recursiveRead(path, '*.php')
        print("Found {}{}{} files with php extension, testing them..\n".format(colors.GREEN, len(files), colors.END))
        for file in files:
            res = self.testFile(file)
            results.append(res)
        return results

    # Test file against common vulnerabilities
    def testFile(self, path):
        print("Testing file: {}".format(path))
        res = {
            "name": path,
            "total": 0,
            "data": {
                "xss": [],
                "sql": [],
                "fid": [],
                "fin": [],
                "php": [],
                "com": [],
                "auth": [],
                "pce": [],
                "ope": [],
                "csrf": []
            }
        }
        try:
            code = utils.readfile(path)
            res['data']['xss'] = rules.xss(code)
            res['data']['sql'] = rules.sql(code)
            res['data']['fid'] = rules.fid(code)
            res['data']['fin'] = rules.fin(code)
            res['data']['php'] = rules.php(code)
            res['data']['com'] = rules.com(code)
            res['data']['auth'] = rules.auth(code)
            res['data']['pce'] = rules.pce(code)
            res['data']['ope'] = rules.ope(code)
            res['data']['csfr'] = rules.csrf(code)
            # Get total possible vulnerabilities
            res['total'] = sum(len(arr) for arr in res['data'].values())
            return res
        except Exception as e:
            raise

    # Download a zip archive from url and extract it
    def downloadAndExtract(self, url, path):
        print("Downloading the {}last stable{} version...".format(colors.CYAN, colors.END))
        zFile = utils.downloadZip(url)
        print("\n\nExtracting the archive to: {}{}{}\n".format(colors.CYAN, path, colors.END))
        zFile.extractall(path)
        return path

    # Return the local path where store the archive
    def getArchivePath(self, name):
        outdir = os.getcwd() if self.keep else tempfile.gettempdir()
        if self.keep:
            if isinstance(self.keep, basestring):
                return os.path.join(outdir, self.keep)
            return os.path.join(outdir, name)
        else:
            return os.path.join(outdir, name)

    # Recursively remove all the extracted files
    def clearPath(self, path):
        print("\nRemoving directory {} from filesystem\n".format(path))
        shutil.rmtree(path)

    # TODO: Print a well-formatted scan summary with essential information
    def printReport(self, data):
        # Sort by highest number of findings
        data.sort(key=lambda r: r['total'], reverse=True)
        total = sum(r['total'] for r in data)
        totalFiles = "{}{}{}".format(colors.GREEN, len(data), colors.END)
        totalFindings = "{}{}{}".format(colors.RED, total, colors.END)
        if total == 0:
            print("The scan ended with {}no results{} found, scanned {} files".format(colors.RED, colors.END, totalFiles))
        else:
            print("Found {} possible vulnerabilities in {} files".format(totalFindings, totalFiles))

# Run the script
if __name__ == "__main__":
    print BANNER
    parser = argparse.ArgumentParser(epilog=USAGE, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("source", help="Can be slug, url, a path to file or directory")
    parser.add_argument("-s", "--save", help="Save the scan results to JSON in current folder", action='store_true')
    parser.add_argument("-k", "--keep", help="Enable to keep the downloaded zip archive",
                        action='store', nargs='?', const=True, default=False, metavar='name')
    args = parser.parse_args()
    try:
        wpsploit(args).main()
    except KeyboardInterrupt, e:
        exit()
