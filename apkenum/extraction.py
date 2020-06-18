import re
import logging

from androguard import misc

logger = logging.getLogger(__name__)

class APKSource:
    def __init__(self, apk_file):
        self.apk_file = apk_file

    def analyze(self):
        a, d, dx = misc.AnalyzeAPK(self.apk_file)
        self.apk = a
        self.dalvik_format = d
        self.analysis = dx

    def find_raw_strings(self, regex):
        return [str_analysis.get_orig_value() for str_analysis in self.analysis.find_strings(regex)]

class InformatioExtractor:
    def __init__(self):
        pass

    def process(self, apk_source):
        raise NotImplementedError

    def results(self):
        raise NotImplementedError

class URLsExtractor(InformatioExtractor):
    URL_REGEX = r'(http|ftp|https)://([\w_-]+(?:(?:\.[\w_-]+)+):?\d*)([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?' #regex to extract domain

    def __init__(self):
        super().__init__()
        self.urls = set()

    def process(self, apk_source):
        self.urls = self.urls.union(apk_source.find_raw_strings(URLsExtractor.URL_REGEX))

    def results(self):
        return self.urls


class IPsExtractor(InformatioExtractor):
    IP_REGEX = r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}'

    def __init__(self):
        super().__init__()
        self.ips = set()

    def process(self, apk_source):
        self.ips = self.ips.union(apk_source.find_raw_strings(IPsExtractor.IP_REGEX))

    def results(self):
        return self.ips

class S3BucketsExtractor(InformatioExtractor):
    S3_REGEX1 = r"https*://(.+?)\.s3\..+?\.amazonaws\.com\/.+?"
    S3_REGEX2 = r"https*://s3\..+?\.amazonaws\.com\/(.+?)\/.+?"
    S3_REGEX3 = r"S3://(.+?)/"

    def __init__(self):
        super().__init__()
        self.buckets = set()

    def process(self, apk_source):
        self.buckets = self.buckets.union(apk_source.find_raw_strings(S3BucketsExtractor.S3_REGEX1))
        self.buckets = self.buckets.union(apk_source.find_raw_strings(S3BucketsExtractor.S3_REGEX2))
        self.buckets = self.buckets.union(apk_source.find_raw_strings(S3BucketsExtractor.S3_REGEX3))

    def results(self):
        return self.buckets

class S3URLsExtrctor(InformatioExtractor):
    S3_WEBSITE_REGEX1 = r"https*://(.+?)\.s3-website\..+?\.amazonaws\.com"
    S3_WEBSITE_REGEX2 = r"https*://(.+?)\.s3-website-.+?\.amazonaws\.com"

    def __init__(self):
        super().__init__()
        self.urls = set()

    def process(self, apk_source):
        self.urls = self.urls.union(apk_source.find_raw_strings(S3URLsExtrctor.S3_WEBSITE_REGEX1))
        self.urls = self.urls.union(apk_source.find_raw_strings(S3URLsExtrctor.S3_WEBSITE_REGEX2))

    def results(self):
        return self.urls

class PermissionsExtractor(InformatioExtractor):
    MANIFEST_FILE_PATTERN = r".*AndroidManifest.xml$"

    def __init__(self):
        super().__init__()
        self.permissions = set()

    def process(self, apk_source):
        self.permissions = self.permissions.union(apk_source.apk.get_permissions())

    def results(self):
        return self.permissions

