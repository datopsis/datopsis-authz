"""Build-only fallback for three relocated, immutable PGDG RPMs.

The pinned owner acquirer still checks its ORIGINAL size, SHA-256 and RPM signer.
No runtime HTTP, TLS, lockfile or repository source changes are made.
"""
import urllib.error
import urllib.request

_ORIGINAL_OPEN = urllib.request.OpenerDirector.open
_PREFIX = 'https://download.postgresql.org/pub/repos/yum/18/redhat/rhel-9-x86_64/'
_MIRROR = 'https://download.postgresql.org/pub/repos/yum/18/redhat/rhel-9.8-x86_64/'
_FILES = {
    'postgresql18-18.6-1PGDG.rhel9.8.x86_64.rpm',
    'postgresql18-libs-18.6-1PGDG.rhel9.8.x86_64.rpm',
    'postgresql18-server-18.6-1PGDG.rhel9.8.x86_64.rpm',
}


def _open(self, fullurl, *args, **kwargs):
    try:
        return _ORIGINAL_OPEN(self, fullurl, *args, **kwargs)
    except urllib.error.HTTPError as exc:
        url = fullurl.full_url if isinstance(fullurl, urllib.request.Request) else fullurl
        if exc.code != 404 or url not in {_PREFIX + name for name in _FILES}:
            raise
        # Only public GET/HEAD artifact requests; never forward credentials.
        headers = dict(fullurl.header_items()) if isinstance(fullurl, urllib.request.Request) else {}
        assert not any(k.lower() in ('authorization', 'cookie') for k in headers)
        method = fullurl.get_method() if isinstance(fullurl, urllib.request.Request) else 'GET'
        assert method in ('GET', 'HEAD')
        mirror = url.replace(_PREFIX, _MIRROR, 1)
        print('S2 locked-artifact fallback: '+url+' -> '+mirror, flush=True)
        return _ORIGINAL_OPEN(self, urllib.request.Request(mirror, headers=headers, method=method), *args, **kwargs)


urllib.request.OpenerDirector.open = _open
