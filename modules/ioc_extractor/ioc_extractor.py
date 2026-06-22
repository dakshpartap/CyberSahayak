import re


def extract_iocs(text):

    return {
        "urls": list(set(re.findall(
            r'https?://[^\s]+',
            text
        ))),

        "emails": list(set(re.findall(
            r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}',
            text
        ))),

        "ips": list(set(re.findall(
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            text
        ))),

        "domains": list(set(re.findall(
            r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b',
            text
        ))),

        "md5": list(set(re.findall(
            r'\b[a-fA-F0-9]{32}\b',
            text
        ))),

        "sha1": list(set(re.findall(
            r'\b[a-fA-F0-9]{40}\b',
            text
        ))),

        "sha256": list(set(re.findall(
            r'\b[a-fA-F0-9]{64}\b',
            text
        )))
    }