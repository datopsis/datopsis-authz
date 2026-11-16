"""Build-only transport fallback for immutable PGDG 18.6 / RHEL 9.8 inputs.

Loaded only by the fixture build's explicit PYTHONPATH. Never edit owner sources
or locks. Their acquisition code still verifies HTTPS origin, exact size/SHA-256,
key fingerprints and RPM signatures. Only a 404 for one exact package family on
the publisher's rolling alias can use its matching minor-release directory.
"""
import re
import urllib.error
import urllib.request

_PATTERN = re.compile(
    r'https://download\.postgresql\.org/pub/repos/yum/18/redhat/'
    r'rhel-9-(?P<arch>x86_64|aarch64)/'
    r'postgresql18(?:-contrib|-libs|-server)?-18\.6-1PGDG\.rhel9\.8\.(?P=arch)\.rpm'
)
_ORIGINAL = urllib.request.OpenerDirector.open


def _open(self, fullurl, *args, **kwargs):
    try:
        return _ORIGINAL(self, fullurl, *args, **kwargs)
    except urllib.error.HTTPError as error:
        url = fullurl.full_url if isinstance(fullurl, urllib.request.Request) else fullurl
        if error.code != 404 or not _PATTERN.fullmatch(url):
            raise
        alternate = url.replace('/rhel-9-', '/rhel-9.8-')
        print('Pinned PGDG artifact 404; using same-publisher minor path: '+alternate, flush=True)
        if isinstance(fullurl, urllib.request.Request):
            alternate = urllib.request.Request(alternate, data=fullurl.data,
                                               headers=dict(fullurl.header_items()),
                                               method=fullurl.get_method())
        return _ORIGINAL(self, alternate, *args, **kwargs)


urllib.request.OpenerDirector.open = _open
