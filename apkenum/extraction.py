import os
import re
import logging
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

class APKSource:
    def __init__(self, root_dir):
        self.root_dir = root_dir


    def files(self):
        for dir_path, _, file_names in os.walk(self.root_dir):
            for file_name in file_names:
                fullpath = os.path.join(dir_path, file_name)
                logger.debug("Adding file (%s) to file list", fullpath)
                yield fullpath


class InformatioExtractor:
    def __init__(self):
        pass

    def process(self, filename, filecontent):
        raise NotImplementedError

    def results(self):
        raise NotImplementedError

class URLsExtractor(InformatioExtractor):
    URL_REGEX = r'(http|ftp|https)://([\w_-]+(?:(?:\.[\w_-]+)+):?\d*)([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?' #regex to extract domain

    def __init__(self):
        super().__init__()
        self.urls = set()

    def process(self, filename, filecontent):
        data = filecontent.decode('utf-8')
        results = re.findall(URLsExtractor.URL_REGEX, data)
        for el in results:
            self.urls.add(el[0]+"://"+el[1])

    def results(self):
        return self.urls


class IPsExtractor(InformatioExtractor):
    IP_REGEX = r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}'

    def __init__(self):
        super().__init__()
        self.ips = set()

    def process(self, filename, filecontent):
        data = filecontent.decode('utf-8')
        results = re.findall(IPsExtractor.IP_REGEX, data)
        for el in results:
            self.ips.add(el)

    def results(self):
        return self.ips

class S3BucketsExtractor(InformatioExtractor):
    S3_REGEX1 = r"https*://(.+?)\.s3\..+?\.amazonaws\.com\/.+?"
    S3_REGEX2 = r"https*://s3\..+?\.amazonaws\.com\/(.+?)\/.+?"
    S3_REGEX3 = r"S3://(.+?)/"

    def __init__(self):
        super().__init__()
        self.buckets = set()

    def process(self, filename, filecontent):
        data = filecontent.decode('utf-8')
        results = re.findall(S3BucketsExtractor.S3_REGEX1, data)
        for el in results:
            self.buckets.add(el)
        results = re.findall(S3BucketsExtractor.S3_REGEX2, data)
        for el in results:
            self.buckets.add(el)
        results = re.findall(S3BucketsExtractor.S3_REGEX3, data)
        for el in results:
            self.buckets.add(el)

    def results(self):
        return self.buckets

class S3URLsExtrctor(InformatioExtractor):
    S3_WEBSITE_REGEX1 = r"https*://(.+?)\.s3-website\..+?\.amazonaws\.com"
    S3_WEBSITE_REGEX2 = r"https*://(.+?)\.s3-website-.+?\.amazonaws\.com"

    def __init__(self):
        super().__init__()
        self.urls = set()

    def process(self, filename, filecontent):
        data = filecontent.decode('utf-8')
        results = re.findall(S3URLsExtrctor.S3_WEBSITE_REGEX1, data)
        for el in results:
            self.urls.add(el)
        results = re.findall(S3URLsExtrctor.S3_WEBSITE_REGEX2, data)
        for el in results:
            self.urls.add(el)

    def results(self):
        return self.urls

class PermissionsExtractor(InformatioExtractor):
    MANIFEST_FILE_PATTERN = r".*AndroidManifest.xml$"

    def __init__(self):
        super().__init__()
        self.permissions = set()

    def process(self, filename, filecontent):
        if re.match(PermissionsExtractor.MANIFEST_FILE_PATTERN, filename):
            logger.debug("Extracting permissions from (%s)", filename)
            root = ET.fromstring(filecontent)
            perms = [tag.attrib['{http://schemas.android.com/apk/res/android}name'] for tag in root.iter('uses-permission')]
            self.permissions.update(perms)

    def results(self):
        return self.permissions

