#!/bin/bash
export PYTHONPATH=/usr/lib/python3/dist-packages:/usr/local/lib/python3.13/dist-packages:/usr/lib/python3.13
cd /home/kali/project-aegis
exec /usr/bin/python3 daemon.py
