import os
import sys
import re
import glob
import fnmatch
import urllib
import string
import random

from colors import colors

# For requesting plugin and downloading it
from urlparse import urlparse
from urllib2 import urlopen

# For reading and extracting zip file
from StringIO import StringIO
from zipfile import ZipFile

# Unix path regex
UNIXPATH = r'^\/$|(^(?=\/)|^\.|^\.\.)(\/(?=[^/\0])[^/\0]+)*\/?$'

# Windows path regex
WINPATH = r'^([a-z]:\\|.\\)(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*$'

class utils(object):

    # Generate a random string of chars with optional length
    @staticmethod
    def randomString(size=6, chars=string.ascii_uppercase + string.digits):
        return ''.join(random.choice(chars) for _ in range(size))

    # Test if a given string is possibly a Unix or Windows path
    @staticmethod
    def validatePath(path):
        return (
            re.search(UNIXPATH, path, re.IGNORECASE) or
            re.search(WINPATH, path, re.IGNORECASE)
        )

    # Test if a given input is valid URL
    @staticmethod
    def validateURL(url):
        return urlparse(url).netloc != ''

    # Test if the url matches the WordPress.org repository format
    # and extract the informations about the repository (kind and name)
    @staticmethod
    def extractInformations(url):
        matches = re.search(r'wordpress.org/(theme[s]?|plugin[s]?)/([\w-]+)', url, re.IGNORECASE)
        if matches:
            matches = matches.groups()
        return matches

    # Build the zip download url for a given name
    @staticmethod
    def getDownloadPath(name, kind='plugin'):
        return "https://downloads.wordpress.org/{}/{}.latest-stable.zip?nostats=1".format(kind, name)

    # Build the link to the latest repository archive
    @staticmethod
    def buildDownloadUrl(name, kind="plugin"):
        return "https://downloads.wordpress.org/{}/{}.latest-stable.zip?nostats=1".format(kind, name)

    # Test WordPress plugin directory for existence by slug
    @staticmethod
    def validateWordPressURL(name):
        url = "https://wordpress.org/plugins/{}/".format(name)
        try:
            urlopen = urllib.URLopener()
            r = urlopen.open(url)
            return True
        except Exception as e:
            return False

    # Print a result line
    @staticmethod
    def printLine(line, label, value):
        line = "{}[L{}]{}".format(colors.GREEN, line, colors.END)
        label = "{}{}{}".format(colors.GREEN, label, colors.END)
        value = "{}{}{}".format(colors.RED, value, colors.END)
        print " {} Possibile {} ==> {}".format(line, label, value)

    # Read a file line by line and get an array of code
    @staticmethod
    def readfile(filename):
        codelist = []
        try:
            file = open(filename, "rb+")
            for line in file.readlines():
                line = line.split("\r\n")[0]
                codelist.append(line)
            return codelist
        except IOError, e:
            raise e

    # Print a customizable progress bar to stdout
    @staticmethod
    def progress(count, total, status=''):
        bar_len = 60
        filled_len = int(round(bar_len * count / float(total)))
        percents = round(100.0 * count / float(total), 1)
        bar = '=' * filled_len + '-' * (bar_len - filled_len)
        sys.stdout.write('[%s] %s%s ...%s\r' % (bar, percents, '%', status))
        sys.stdout.flush()

    # Download a zip archive from url showing a progress bar
    # than returns a ZipFile opened in memory
    @staticmethod
    def downloadZip(url):
        data = ''
        bytesRead = 0
        chunkSize = 1024
        try:
            zipresp = urlopen(url)
            totalSize = int(zipresp.info().getheader('Content-Length').strip())
            while 1:
                chunk = zipresp.read(chunkSize)
                bytesRead += len(chunk)
                if not chunk:
                    break
                data += chunk
                utils.progress(bytesRead, totalSize, 'DOWNLOADING')
            return ZipFile(StringIO(data))
        except Exception as e:
            raise Exception(e)

    # Get all files in a filder that match given pattern
    @staticmethod
    def recursiveRead(rootdir, pattern):
        matches = []
        for root, dirnames, filenames in os.walk(rootdir):
            for filename in fnmatch.filter(filenames, pattern):
                matches.append(os.path.join(root, filename))
        return matches
