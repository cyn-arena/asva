import os
import time

import requests
from django.contrib.auth import authenticate, login
from django.http import JsonResponse
from django.shortcuts import redirect
from django.views.decorators.csrf import csrf_exempt

from introduction.playground.A6.utility import check_vuln
from introduction.playground.A9.main import Log
from introduction.playground.ssrf import main

from .utility import *
from .views import authentication_decorator


def _is_safe_ssrf_lab_input(value):
    if not isinstance(value, str) or not value or "\x00" in value:
        return False
    if os.path.isabs(value):
        return False
    if len(value) >= 2 and value[1] == ':' and value[0].isalpha():
        return False
    normalized = value.replace('\\', '/')
    if normalized.startswith('/'):
        return False
    if '..' in normalized.split('/'):
        return False
    return True


# steps --> 
# 1. covert input code to corrosponding code and write in file