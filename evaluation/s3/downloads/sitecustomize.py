"""Build-only routing for immutable PGDG 18.6 / RHEL 9.8 inputs.

Loaded only by the fixture build's explicit PYTHONPATH. Never edit owner sources
or locks. Their acquisition code still verifies HTTPS origin, exact size/SHA-256,
key fingerprints and RPM signatures. Only this exact package family on the
publisher's rolling alias uses its matching minor-release directory. The alias
has returned both 404 and an incomplete 200 body in native Actions.
"""
import re
import urllib.request

_PATTERN = re.compile(
    r'https://download\.postgresql\.org/pub/repos/yum/18/redhat/'
    r'rhel-9-(?P<arch>x86_64|aarch64)/'
    r'postgresql18(?:-contrib|-libs|-server)?-18\.6-1PGDG\.rhel9\.8\.(?P=arch)\.rpm'
)
_ORIGINAL = urllib.request.OpenerDirector.open


def _open(self, fullurl, *args, **kwargs):
    url = fullurl.full_url if isinstance(fullurl, urllib.request.Request) else fullurl
    if _PATTERN.fullmatch(url):
        alternate = url.replace('/rhel-9-', '/rhel-9.8-')
        print('Pinned PGDG artifact: using verified same-publisher minor path: '+alternate, flush=True)
        if isinstance(fullurl, urllib.request.Request):
            fullurl = urllib.request.Request(alternate, data=fullurl.data,
                                             headers=dict(fullurl.header_items()),
                                             method=fullurl.get_method())
        else:
            fullurl = alternate
    return _ORIGINAL(self, fullurl, *args, **kwargs)


urllib.request.OpenerDirector.open = _open
