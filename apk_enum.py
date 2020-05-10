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
authorityList = []
inScopeAuthorityList = []
publicIpList = []
s3List = []
s3WebsiteList = []


urlRegex = r'(http|ftp|https)://([\w_-]+(?:(?:\.[\w_-]+)+):?\d*)([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?' #regex to extract domain
apktoolPath = "./Dependencies/apktool.jar"
s3Regex1 = r"https*://(.+?)\.s3\..+?\.amazonaws\.com\/.+?"
s3Regex2 = r"https*://s3\..+?\.amazonaws\.com\/(.+?)\/.+?"
s3Regex3 = r"S3://(.+?)/"
s3Website1 = r"https*://(.+?)\.s3-website\..+?\.amazonaws\.com"
s3Website2 = r"https*://(.+?)\.s3-website-.+?\.amazonaws\.com"
publicIp = r'https*://(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!172\.(16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31))(?<!127)(?<!^10)(?<!^0)\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!192\.168)(?<!172\.(16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31))\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!\.255$))'

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

    if category == "INFO" :
        print(txt_color_info+txt_color_bold+text+txt_color_endc+"\n")
    if category == "INFO_WS" :
        print(txt_color_info+txt_color_bold+text+txt_color_endc)
    if category == "PLAIN_OUTPUT_WS" :
        print(txt_color_info+text+txt_color_endc)
    if category == "ERROR" :
        print(txt_color_bgred+txt_color_fgwhite+txt_color_bold+text+txt_color_endc)
    if category == "MESSAGE_WS" :
        print(txt_color_title+txt_color_bold+text+txt_color_endc)
    if category == "MESSAGE" :
        print(txt_color_title+txt_color_bold+text+txt_color_endc+"\n")
    if category == "INSECURE" :
        print(txt_color_okred+txt_color_bold+text+txt_color_endc+"\n")
    if category == "INSECURE_WS" :
        print(txt_color_okred+txt_color_bold+text+txt_color_endc)
    if category == "OUTPUT" :
        print(txt_color_okblue+txt_color_bold+text+txt_color_endc+"\n")
    if category == "OUTPUT_WS" :
        print(txt_color_okblue+txt_color_bold+text+txt_color_endc)
    if category == "SECURE_WS" :
        print(txt_color_okgreen+txt_color_bold+text+txt_color_endc)
    if category == "SECURE" :
        print(txt_color_okgreen+txt_color_bold+text+txt_color_endc+"\n")


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
        exit(1)
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
    projectDir=rootDir+apkFileName+"_"+hashlib.md5().hexdigest()
    if (os.path.exists(projectDir)==True):
        color_print("I: The APK is already decompiled. Skipping decompilation and proceeding with scanning the application.", "INFO_WS")
        return projectDir
    os.mkdir(projectDir)
    color_print("I: Decompiling the APK file using APKtool.", "INFO_WS")
    result=os.system("java -jar "+apktoolPath+" d "+"--output "+'"'+projectDir+"/apktool/"+'"'+' "'+apkFilePath+'"'+'>/dev/null')
    if (result!=0):
        logging.error("E: Apktool failed with exit status "+str(result)+". Please Try Again.")
        exit(1)
    color_print("I: Successfully decompiled the application. Proceeding with scanning code.", "INFO_WS")

def findS3Bucket(line):
    temp=re.findall(s3Regex1,line)
    if (len(temp)!=0):
        for element in temp:
            s3List.append(element)


    temp=re.findall(s3Regex2,line)
    if (len(temp)!=0):
        for element in temp:
            s3List.append(element)


    temp=re.findall(s3Regex3,line)
    if (len(temp)!=0):
        for element in temp:
            s3List.append(element)


def findS3Website(line):
    temp=re.findall(s3Website1,line)
    if (len(temp)!=0):
        for element in temp:
            s3WebsiteList.append(element)

    temp=re.findall(s3Website2,line)
    if (len(temp)!=0):
        print(temp)
        for element in temp:
            s3WebsiteList.append(element)


def findUrls(line):
    temp=re.findall(urlRegex,line)
    if (len(temp)!=0):
        for element in temp:
            authorityList.append(element[0]+"://"+element[1])
            if(scopeMode):
                for scope in scopeList:
                    if scope in element[1]:
                        inScopeAuthorityList.append(element[0]+"://"+element[1])

def findPublicIPs(line):
    temp=re.findall(publicIp,line)
    if (len(temp)!=0):
        for element in temp:
            publicIpList.append(element[0])


def identifyURLs():
    filecontent = ""
    for dir_path, _, file_names in os.walk(rootDir+apkFileName+"_"+hashlib.md5().hexdigest()):
        for file_name in file_names:
            try:
                fullpath = os.path.join(dir_path, file_name)
                fileobj = open(fullpath, mode='r')
                filecontent = fileobj.read()
                fileobj.close()
            except Exception as exc:
                logging.error("E: Exception while reading  "+fullpath)
                logging.error(exc)

            try:
                threads = map(
                    lambda  op:  threading.Thread(target=op, args=(filecontent,)),
                    [findUrls, findPublicIPs, findS3Bucket, findS3Website])
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()
            except Exception as exc:
                logging.error("E:  Error  while  spawning  threads")
                logging.error(exc)

def displayResults():
    global inScopeAuthorityList, authorityList, s3List, s3WebsiteList, publicIpList
    inScopeAuthorityList=list(set(inScopeAuthorityList))
    authorityList=list(set(authorityList))
    s3List=list(set(s3List))
    s3WebsiteList=list(set(s3WebsiteList))
    publicIpList=list(set(publicIpList))
    if (len(authorityList)==0):
        color_print("\nNo URL found", "INSECURE")
    else:
        color_print("\nList of URLs found in the application", "SECURE")
        printList(authorityList)

    if(scopeMode and len(inScopeAuthorityList)==0):
        color_print("\nNo in-scope URL found", "INSECURE")
    elif scopeMode:
        color_print("\nList of in scope URLs found in the application", "SECURE")
        printList(inScopeAuthorityList)

    if (len(s3List)==0):
        color_print("\nNo S3 buckets found", "INSECURE")
    else:
        color_print("\nList of in S3 buckets found in the application", "SECURE")
        printList(s3List)

    if (len(s3WebsiteList)==0):
        color_print("\nNo S3 websites found", "INSECURE")
    else:
        color_print("\nList of in S3 websites found in the application", "SECURE")
        printList(s3WebsiteList)

    if (len(publicIpList)==0):
        color_print("\nNo IPs found", "INSECURE")
    else:
        color_print("\nList of IPs found in the application", "SECURE")
        printList(publicIpList)

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

         # Developed By Shiv Sahni - @shiv__sahni
""")

if ((len(sys.argv)==2) and (sys.argv[1]=="-h" or sys.argv[1]=="--help")):
    print("Usage: python APKEnum.py -p/--path <apkPathName> [ -s/--scope \"comma, seperated, list\"]")
    print("\t-p/--path: Pathname of the APK file")
    print("\t-s/--scope: List of keywords to filter out domains")
    exit(1)

if (len(sys.argv)<3):
    print("E: Please provide the required arguments to initiate")
    print()
    print("E: Usage: python APKEnum.py -p/--path <apkPathName> [ -s/--scope \"comma, seperated, list\"]")
    print("E: Please try again!!", "ERROR")
    exit(1)

if ((len(sys.argv)>4) and (sys.argv[3]=="-s" or sys.argv[3]=="--scope")):
    scopeString=sys.argv[4].strip()
    scopeList=scopeString.split(',')
    if len(scopeList)!=0:
        scopeMode=True

if (sys.argv[1]=="-p" or sys.argv[1]=="--path"):
    apkFilePath=sys.argv[2]
    try:
        isNewInstallation()
        isValidPath(apkFilePath)
        reverseEngineerApplication(apkFileName)
        identifyURLs()
        displayResults()
    except KeyboardInterrupt:
        color_print("I: Acknowledging KeyboardInterrupt. Thank you for using APKEnum", "INFO")
        exit(0)
color_print("Thank You For Using APKEnum","OUTPUT")
