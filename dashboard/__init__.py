"""Read-only SIEM-style dashboard for the IPS.

Consumes ips_events.log (the sniffer's forensic output) and serves live and
aggregate views over HTTP. Contains no detection or response logic of its
own — see Handling/ for the production pipeline.
"""

__version__ = "1.0.0"
