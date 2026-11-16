"""Transport-only fallback for PGDG's moved, hash-locked 18.6 RPMs.

The unchanged owner acquirer still checks locked size/SHA256, key fingerprints,
and RPM signatures. No source/lock changes, TLS overrides, or version fallback.
Only enabled for child Python processes during the fixture image build.
"""
import re
import urllib.error
import urllib.request

_original_open = urllib.request.OpenerDirector.open
_PATTERN = re.compile(
    r'^https://download\.postgresql\.org/pub/repos/yum/18/redhat/'
    r'rhel-9-(?P<arch>x86_64|aarch64)/'
    r'postgresql18(?:-contrib|-libs|-server)?-18\.6-1PGDG\.rhel9\.8\.(?P=arch)\.rpm$'
)


def _open(self, request, *args, **kwargs):
    url = request.full_url if isinstance(request, urllib.request.Request) else request
    try:
        return _original_open(self, request, *args, **kwargs)
    except urllib.error.HTTPError as exc:
        if exc.code != 404 or not _PATTERN.fullmatch(url):
            raise
        target = url.replace('/rhel-9-', '/rhel-9.8-', 1)
        print('S4 locked PGDG transport fallback: '+url+' -> '+target, flush=True)
        if isinstance(request, urllib.request.Request):
            request = urllib.request.Request(target, data=request.data,
                headers=dict(request.header_items()), method=request.get_method())
        else:
            request = target
        return _original_open(self, request, *args, **kwargs)


urllib.request.OpenerDirector.open = _open
