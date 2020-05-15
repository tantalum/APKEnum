#!/usr/bin/python
import os
import sys
import re
import threading
import logging
import argparse
import tempfile

class APKEnumReport:
    """Encapsulates the results of the APK analysis"""
    def __init__(self):
        self.url_list = set()
        self.ip_list = set()
        self.s3_bucket_list = set()
        self.s3_website_list = set()

    def add_url(self, url):
        self.url_list.add(url)

    def add_ip(self, ip):
        self.ip_list.add(ip)

    def add_s3_bucket(self, s3_bucket):
        self.s3_bucket_list.add(s3_bucket)

    def add_s3_website(self, s3_website):
        self.s3_website_list.add(s3_website)


URL_REGEX = r'(http|ftp|https)://([\w_-]+(?:(?:\.[\w_-]+)+):?\d*)([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?' #regex to extract domain
APKTOOL_PATH = "./Dependencies/apktool.jar"
S3_REGEX1 = r"https*://(.+?)\.s3\..+?\.amazonaws\.com\/.+?"
S3_REGEX2 = r"https*://s3\..+?\.amazonaws\.com\/(.+?)\/.+?"
S3_REGEX3 = r"S3://(.+?)/"
S3_WEBSITE_REGEX1 = r"https*://(.+?)\.s3-website\..+?\.amazonaws\.com"
S3_WEBSITE_REGEX2 = r"https*://(.+?)\.s3-website-.+?\.amazonaws\.com"
PUBLIC_IP_REGEX = r'https*://(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!172\.(16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31))(?<!127)(?<!^10)(?<!^0)\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!192\.168)(?<!172\.(16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31))\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!\.255$))'

def color_print(text, category):
    txt_color_title = '\033[95m'
    txt_color_okblue = '\033[94m'
    txt_color_okgreen = '\033[92m'
    txt_color_info = '\033[93m'
    txt_color_okred = '\033[91m'
    txt_color_endc = '\033[0m'
    txt_color_bold = '\033[1m'
    txt_color_bgred = '\033[41m'
    txt_color_fgwhite = '\033[37m'

    if category == "INFO":
        print(txt_color_info + txt_color_bold + text + txt_color_endc + "\n")
    if category == "INFO_WS":
        print(txt_color_info + txt_color_bold + text + txt_color_endc)
    if category == "PLAIN_OUTPUT_WS":
        print(txt_color_info + text + txt_color_endc)
    if category == "ERROR":
        print(txt_color_bgred + txt_color_fgwhite + txt_color_bold + text + txt_color_endc)
    if category == "MESSAGE_WS":
        print(txt_color_title + txt_color_bold + text + txt_color_endc)
    if category == "MESSAGE":
        print(txt_color_title + txt_color_bold + text + txt_color_endc + "\n")
    if category == "INSECURE":
        print(txt_color_okred + txt_color_bold + text + txt_color_endc + "\n")
    if category == "INSECURE_WS":
        print(txt_color_okred + txt_color_bold + text + txt_color_endc)
    if category == "OUTPUT":
        print(txt_color_okblue + txt_color_bold + text + txt_color_endc + "\n")
    if category == "OUTPUT_WS":
        print(txt_color_okblue + txt_color_bold + text + txt_color_endc)
    if category == "SECURE_WS":
        print(txt_color_okgreen + txt_color_bold + text + txt_color_endc)
    if category == "SECURE":
        print(txt_color_okgreen + txt_color_bold + text + txt_color_endc + "\n")



def printList(lst):
    counter=0
    for item in lst:
        counter=counter+1
        entry=str(counter)+". "+item
        color_print(entry, "PLAIN_OUTPUT_WS")

def findS3Bucket(line, report):
    temp=re.findall(S3_REGEX1,line)
    if (len(temp)!=0):
        for element in temp:
            report.add_s3_bucket(element)


    temp=re.findall(S3_REGEX2,line)
    if (len(temp)!=0):
        for element in temp:
            report.add_s3_bucket(element)


    temp=re.findall(S3_REGEX3,line)
    if (len(temp)!=0):
        for element in temp:
            report.add_s3_bucket(element)


def findS3Website(line, report):
    temp=re.findall(S3_WEBSITE_REGEX1,line)
    if (len(temp)!=0):
        for element in temp:
            report.add_s3_website(element)

    temp=re.findall(S3_WEBSITE_REGEX2,line)
    if (len(temp)!=0):
        print(temp)
        for element in temp:
            report.add_s3_website(element)

def findUrls(line, report):
    temp=re.findall(URL_REGEX,line)
    if (len(temp)!=0):
        for element in temp:
            report.add_url(element[0]+"://"+element[1])

def findPublicIPs(line, report):
    temp=re.findall(PUBLIC_IP_REGEX,line)
    if (len(temp)!=0):
        for element in temp:
            report.add_ip(element[0])


def identifyURLs(project_dir, report):
    filecontent = ""
    for dir_path, _, file_names in os.walk(project_dir):
        for file_name in file_names:
            try:
                fullpath = os.path.join(dir_path, file_name)
                fileobj = open(fullpath, mode='r')
                filecontent = fileobj.read()
                fileobj.close()
            except Exception as exc:
                logging.error("E: Exception while reading  %s", fullpath)
                logging.error(exc)

            try:
                threads = map(
                    lambda  op:  threading.Thread(target=op, args=(filecontent, report,)),
                    [findUrls, findPublicIPs, findS3Bucket, findS3Website])
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()
            except Exception as exc:
                logging.error("E:  Error  while  spawning  threads")
                logging.error(exc)

def displayResults(report):
    if len(report.url_list) == 0:
        color_print("\nNo URL found", "INSECURE")
    else:
        color_print("\nList of URLs found in the application", "SECURE")
        printList(report.url_list)

    if len(report.s3_bucket_list) == 0:
        color_print("\nNo S3 buckets found", "INSECURE")
    else:
        color_print("\nList of in S3 buckets found in the application", "SECURE")
        printList(report.s3_bucket_list)

    if len(report.s3_website_list) == 0:
        color_print("\nNo S3 websites found", "INSECURE")
    else:
        color_print("\nList of in S3 websites found in the application", "SECURE")
        printList(report.s3_website_list)

    if len(report.ip_list) == 0:
        color_print("\nNo IPs found", "INSECURE")
    else:
        color_print("\nList of IPs found in the application", "SECURE")
        printList(report.ip_list)

####################################################################################################

def main(args):
    # Parse the command line arguments
    argsparser = argparse.ArgumentParser(description="Find interesting things in Android APKs")
    argsparser.add_argument('-s', '--source', help="The source directory."
            + "This is the directory the APK has been decompiled to using `apktool`."
            + "Cannot be used with other options.")
    argsparser.add_argument('-a', '--apk', help="The APK file to decompile")
    argsparser.add_argument('-t', '--tool', help="The path to `apktool` to use")
    argsparser.add_argument('-d', '--dest', help="The desitination directory to decompile the APK into."
            + "If not defined a temporary directory is created.")
    parsedargs = argsparser.parse_args(args)

    project_dir = None
    if parsedargs.source is not None:
        if parsedargs.apk is not None or parsedargs.tool is not None or parsedargs.dest is not None:
            logging.error("Invalid arguments: --source cannot be combined with any other options")
            argsparser.print_usage()
            sys.exit(1)
        project_dir = parsedargs.source
    elif parsedargs.apk is not None:
        apk_path = parsedargs.apk
        apk_tool = 'apktool'
        if parsedargs.tool is not None:
            apk_tool = parsedargs.tool
        if parsedargs.dest is not None:
            project_dir = parsedargs.dest
        else:
            project_dir = tempfile.mkdtemp(prefix="apkenum")

        logging.warn("Decompiling (%s) into (%s) using apktool (%s)", apk_path, project_dir, apk_tool)
        result = os.system(apk_tool + " d "+"-f --output "+'"'+project_dir+'"'+' "'+apk_path+'"'+'>/dev/null')
        if result != 0:
            logging.error("E: Apktool failed with exit status %d. Please Try Again.", result)
            sys.exit(1)
    else:
        argsparser.print_usage()
        sys.exit(1)

    report = APKEnumReport()
    identifyURLs(project_dir, report)
    displayResults(report)

####################################################################################################

if __name__ == '__main__':
    main(sys.argv[1:])
