# APKEnum: Passive Enumeration Utility For Android Applications

![https://www.python.org/static/community_logos/python-logo.png](https://www.python.org/static/community_logos/python-logo.png)


## Installation
### Prerequisites
- Support For Python 3.x
- [APKTool](https://ibotpeaches.github.io/Apktool/) for decompiling an APK.


## Usage
APK Enum takes a decompiled APK file as an input. APK Enum can also take an APK file as input and will decompile the APK using the provided `apktool`.

As of now, the script provides the following information by searching the decompiled code:

* List of domains in the application

* List of S3 buckets referenced in the code

* List of S3 websites referenced in the code

* List of IP addresses referenced in the code

Once downloaded, you just need to provide the pathname of the decompiled APK file as shown below:

```
python APKEnum.py -s /path/to/apktool/output/
```

Optionally, we can also provide an APK for the tool attempt to decompile if possible:

```
python APKEnum.py -a ~/Downloads/app-debug.apk -d /path/to/place/the/decompiled/files/
```
