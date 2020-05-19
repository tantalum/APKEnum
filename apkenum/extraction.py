import os
import re
import logging

logger = logging.getLogger(__name__)

class APKSource:
    def __init__(self, root_dir):
        self.root_dir = root_dir
        self.file_list = None


    def files(self):
        if self.file_list is None:
            self.file_list = []
            for dir_path, _, file_names in os.walk(self.root_dir):
                for file_name in file_names:
                    fullpath = os.path.join(dir_path, file_name)
                    logger.debug("Adding file (%s) to file list", fullpath)
                    self.file_list.append(fullpath)
        return self.file_list

    def find_file(self, matcher):
        return [fname for fname in self.files() if re.match(matcher, fname)]

    def with_files_contents(self, action):
        for fname in self.files():
            try:
                logger.debug("Processing file (%s)", fname)
                with open(fname, 'r') as f:
                    fdata = f.read()
                    action(fdata)
            except Exception as exc:
                logger.error("Error processing file (%s)", fname)
                logger.error(exc)


class InformatioExtractor:
    def __init__(self):
        pass

    def process(self, apk_source):
        raise NotImplementedError

class URLsExtractor(InformatioExtractor):
    URL_REGEX = r'(http|ftp|https)://([\w_-]+(?:(?:\.[\w_-]+)+):?\d*)([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?' #regex to extract domain

    def __init__(self):
        super().__init__()
        self.urls = set()

    def process(self, apk_source):
        apk_source.with_files_contents(self.extrac_urls)
        return self.urls

    def extrac_urls(self, data):
        results = re.findall(URLsExtractor.URL_REGEX, data)
        for el in results:
            self.urls.add(el[0]+"://"+el[1])


class IPsExtractor(InformatioExtractor):
    IP_REGEX = r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}'

    def __init__(self):
        super().__init__()
        self.ips = set()

    def process(self, apk_source):
        apk_source.with_files_contents(self.extract_ips)
        return self.ips

    def extract_ips(self, data):
        results = re.findall(IPsExtractor.IP_REGEX, data)
        for el in results:
            self.ips.add(el)

class S3BucketsExtractor(InformatioExtractor):
    S3_REGEX1 = r"https*://(.+?)\.s3\..+?\.amazonaws\.com\/.+?"
    S3_REGEX2 = r"https*://s3\..+?\.amazonaws\.com\/(.+?)\/.+?"
    S3_REGEX3 = r"S3://(.+?)/"

    def __init__(self):
        super().__init__()
        self.buckets = set()

    def process(self, apk_source):
        apk_source.with_files_contents(self.extract_buckets)
        return self.buckets

    def extract_buckets(self, data):
        results = re.findall(S3BucketsExtractor.S3_REGEX1, data)
        for el in results:
            self.buckets.add(el)
        results = re.findall(S3BucketsExtractor.S3_REGEX2, data)
        for el in results:
            self.buckets.add(el)
        results = re.findall(S3BucketsExtractor.S3_REGEX3, data)
        for el in results:
            self.buckets.add(el)

class S3URLsExtrctor:
    S3_WEBSITE_REGEX1 = r"https*://(.+?)\.s3-website\..+?\.amazonaws\.com"
    S3_WEBSITE_REGEX2 = r"https*://(.+?)\.s3-website-.+?\.amazonaws\.com"

    def __init__(self):
        super().__init__()
        self.urls = set()

    def process(self, apk_source):
        apk_source.with_files_contents(self.extrac_s3_url)
        return self.urls

    def extrac_s3_url(self, data):
        results = re.findall(S3URLsExtrctor.S3_WEBSITE_REGEX1, data)
        for el in results:
            self.urls.add(el)
        results = re.findall(S3URLsExtrctor.S3_WEBSITE_REGEX2, data)
        for el in results:
            self.urls.add(el)

