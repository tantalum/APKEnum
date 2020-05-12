#!/usr/bin/python
import os
import sys
import ntpath
import re
import hashlib
import threading
import logging

rootDir = os.path.expanduser("~")+"/.APKEnum/" #ConfigFolder ~/.SourceCodeAnalyzer/
projectDir = ""
apkFilePath = ""
apkFileName = ""
apkHash = ""
scopeMode = False
scopeList = []


class APKEnumReport:
    """Encapsulates the results of the APK analysis"""
    def __init__(self):
        self.url_list = set()
        self.in_scope_url_list = set()
        self.ip_list = set()
        self.s3_bucket_list = set()
        self.s3_website_list = set()

    def add_url(self, url):
        self.url_list.add(url)

    def add_scoped_url(self, url):
        self.in_scope_url_list.add(url)

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


def isNewInstallation():
    if (os.path.exists(rootDir)==False):
        color_print("Thank you for installing APKEnum", "OUTPUT_WS")
        os.mkdir(rootDir)
        return True
    else:
        return False

def isValidPath(apkFilePath):
    global apkFileName
    color_print("I: Checking if the APK file path is valid.", "INFO_WS")
    if (os.path.exists(apkFilePath)==False):
        color_print("E: Incorrect APK file path found. Please try again with correct file name.", "ERROR")
        print()
        sys.exit(1)
    else:
        color_print("I: APK File Found.", "INFO_WS")
        apkFileName=ntpath.basename(apkFilePath)

def printList(lst):
    counter=0
    for item in lst:
        counter=counter+1
        entry=str(counter)+". "+item
        color_print(entry, "PLAIN_OUTPUT_WS")

def reverseEngineerApplication(apkFileName):
    global projectDir
    color_print("I: Initiating APK decompilation process", "INFO_WS")
    projectDir = rootDir + apkFileName + "_" + hashlib.md5().hexdigest()
    if os.path.exists(projectDir) == True:
        color_print("I: The APK is already decompiled. Skipping decompilation and proceeding with scanning the application.", "INFO_WS")
        return
    os.mkdir(projectDir)
    color_print("I: Decompiling the APK file using APKtool.", "INFO_WS")
    result = os.system("java -jar "+APKTOOL_PATH+" d "+"--output "+'"'+projectDir+"/apktool/"+'"'+' "'+apkFilePath+'"'+'>/dev/null')
    if result != 0:
        logging.error("E: Apktool failed with exit status "+str(result)+". Please Try Again.")
        sys.exit(1)
    color_print("I: Successfully decompiled the application. Proceeding with scanning code.", "INFO_WS")

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
            if(scopeMode):
                for scope in scopeList:
                    if scope in element[1]:
                        report.add_scoped_url(element[0]+"://"+element[1])

def findPublicIPs(line, report):
    temp=re.findall(PUBLIC_IP_REGEX,line)
    if (len(temp)!=0):
        for element in temp:
            report.add_ip(element[0])


def identifyURLs(report):
    filecontent = ""
    for dir_path, _, file_names in os.walk(rootDir+apkFileName+"_"+hashlib.md5().hexdigest()):
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

    if scopeMode and len(report.in_scope_url_list) == 0:
        color_print("\nNo in-scope URL found", "INSECURE")
    elif scopeMode:
        color_print("\nList of in scope URLs found in the application", "SECURE")
        printList(report.in_scope_url_list)

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


####################################################################################################

print("""

:::'###::::'########::'##:::'##:'########:'##::: ##:'##::::'##:'##::::'##:
::'## ##::: ##.... ##: ##::'##:: ##.....:: ###:: ##: ##:::: ##: ###::'###:
:'##:. ##:: ##:::: ##: ##:'##::: ##::::::: ####: ##: ##:::: ##: ####'####:
'##:::. ##: ########:: #####:::: ######::: ## ## ##: ##:::: ##: ## ### ##:
 #########: ##.....::: ##. ##::: ##...:::: ##. ####: ##:::: ##: ##. #: ##:
 ##.... ##: ##:::::::: ##:. ##:: ##::::::: ##:. ###: ##:::: ##: ##:.:: ##:
 ##:::: ##: ##:::::::: ##::. ##: ########: ##::. ##:. #######:: ##:::: ##:
..:::::..::..:::::::::..::::..::........::..::::..:::.......:::..:::::..::

""")

if ((len(sys.argv)==2) and (sys.argv[1]=="-h" or sys.argv[1]=="--help")):
    print("Usage: python APKEnum.py -p/--path <apkPathName> [ -s/--scope \"comma, seperated, list\"]")
    print("\t-p/--path: Pathname of the APK file")
    print("\t-s/--scope: List of keywords to filter out domains")
    sys.exit(1)

if (len(sys.argv)<3):
    print("E: Please provide the required arguments to initiate")
    print()
    print("E: Usage: python APKEnum.py -p/--path <apkPathName> [ -s/--scope \"comma, seperated, list\"]")
    print("E: Please try again!!", "ERROR")
    sys.exit(1)

if ((len(sys.argv)>4) and (sys.argv[3]=="-s" or sys.argv[3]=="--scope")):
    scopeString=sys.argv[4].strip()
    scopeList=scopeString.split(',')
    if len(scopeList)!=0:
        scopeMode=True

if (sys.argv[1]=="-p" or sys.argv[1]=="--path"):
    apkFilePath=sys.argv[2]
    report = APKEnumReport()
    try:
        isNewInstallation()
        isValidPath(apkFilePath)
        reverseEngineerApplication(apkFileName)
        identifyURLs(report)
        displayResults(report)
    except KeyboardInterrupt:
        color_print("I: Acknowledging KeyboardInterrupt. Thank you for using APKEnum", "INFO")
        sys.exit(0)
color_print("Thank You For Using APKEnum", "OUTPUT")
