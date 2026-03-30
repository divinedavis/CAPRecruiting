#!/bin/bash
# Weekly dependency vulnerability check
cd /home/recruiting/bearcats
RESULT=(eval):1: no such file or directory: venv/bin/pip-audit
VULNS=0

if [  -gt 1 ]; then
    echo Mon Mar 30 11:47:48 EDT 2026: Found vulnerabilities: >> /var/log/cap_dep_audit.log
    echo  >> /var/log/cap_dep_audit.log
else
    echo Mon Mar 30 11:47:48 EDT 2026: No vulnerabilities found >> /var/log/cap_dep_audit.log
fi
