import ast
import datetime
import ipaddress
import os
import re
import secrets
import shlex
import subprocess
import tempfile
import time
from hashlib import md5

import jwt
from django.conf import settings
from django.http import HttpResponse, HttpResponseBadRequest, JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt

from .models import CSRF_user_tbl
from .views import authentication_decorator

## Mitre top1 | CWE:787

# target zone
FLAG = "NOT_SUPPOSED_TO_BE_ACCESSED"

# target zone end

_MAX_EXPRESSION_LENGTH = 512
_ALLOWED_BINARY_OPS = {
    ast.Add: lambda left, right: left + right,
    ast.Sub: lambda left, right: left - right,
    ast.Mult: lambda left, right: left * right,
    ast.Div: lambda left, right: left / right,
    ast.FloorDiv: lambda left, right: left // right,
    ast.Mod: lambda left, right: left % right,
    ast.Pow: lambda left, right: left ** right,
}
_ALLOWED_UNARY_OPS = {
    ast.UAdd: lambda value: +value,
    ast.USub: lambda value: -value,
}
_SAFE_NMAP_TARGET_RE = re.compile(r'^(?![.-])[A-Za-z0-9._:/-]{1,253}$')
_SAFE_HOSTNAME_RE = re.compile(
    r'^(?=.{1,253}\Z)(?!-)[A-Za-z0-9_-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))*\.?$'
)
_JWT_SECRET_FILE = os.path.join(tempfile.gettempdir(), 'asva_mitre_jwt_secret')


def _get_jwt_secret():
    secret = os.environ.get('MITRE_JWT_SECRET')
    if secret:
        return secret

    try:
        with open(_JWT_SECRET_FILE, 'r', encoding='utf-8') as secret_file:
            secret = secret_file.read().strip()
            if secret:
                return secret
    except FileNotFoundError:
        pass
    except OSError:
        pass

    secret = secrets.token_urlsafe(32)
    try:
        fd = os.open(_JWT_SECRET_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        for _ in range(100):
            try:
                with open(_JWT_SECRET_FILE, 'r', encoding='utf-8') as secret_file:
                    existing = secret_file.read().strip()
                    if existing:
                        return existing
            except OSError:
                pass
            time.sleep(0.01)
    except OSError:
        pass
    else:
        try:
            os.write(fd, secret.encode('utf-8'))
        finally:
            os.close(fd)
        return secret

    fallback = getattr(settings, 'SECRET_KEY', None)
    if fallback:
        return fallback
    return secrets.token_urlsafe(32)


def _evaluate_ast_node(node):
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (int, float, bool)):
            return node.value
        raise ValueError('Unsupported expression')

    if hasattr(ast, 'Num') and isinstance(node, ast.Num):
        return node.n

    if isinstance(node, ast.BinOp):
        op_type = type(node.op)
        if op_type not in _ALLOWED_BINARY_OPS:
            raise ValueError('Unsupported expression')
        left = _evaluate_ast_node(node.left)
        right = _evaluate_ast_node(node.right)
        if op_type is ast.Pow and abs(right) > 1000:
            raise ValueError('Exponent too large')
        return _ALLOWED_BINARY_OPS[op_type](left, right)

    if isinstance(node, ast.UnaryOp):
        op_type = type(node.op)
        if op_type not in _ALLOWED_UNARY_OPS:
            raise ValueError('Unsupported expression')
        return _ALLOWED_UNARY_OPS[op_type](_evaluate_ast_node(node.operand))

    raise ValueError('Unsupported expression')


def _safe_math_expression(expression):
    if not isinstance(expression, str) or not expression or len(expression) > _MAX_EXPRESSION_LENGTH:
        raise ValueError('Invalid expression')
    try:
        parsed = ast.parse(expression, mode='eval')
    except SyntaxError:
        raise ValueError('Invalid expression')
    return _evaluate_ast_node(parsed.body)


def _is_safe_nmap_target(target):
    if not isinstance(target, str):
        return False
    target = target.strip()
    if not target or len(target) > 253 or target.startswith('-'):
        return False
    if not _SAFE_NMAP_TARGET_RE.fullmatch(target):
        return False
    try:
        if '/' in target:
            ipaddress.ip_network(target, strict=False)
        else:
            ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    return bool(_SAFE_HOSTNAME_RE.fullmatch(target))


def command_out(command):
    if isinstance(command, str):
        command = shlex.split(command)
    process = subprocess.Popen(
        command,
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    return process.communicate()


def _run_nmap(target):
    process = subprocess.Popen(
        ["nmap", target],
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    return process.communicate()


@authentication_decorator
def mitre_top1(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top1.html')

@authentication_decorator
def mitre_top2(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top2.html')

@authentication_decorator
def mitre_top3(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top3.html')
        
@authentication_decorator
def mitre_top4(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top4.html')
        
@authentication_decorator
def mitre_top5(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top5.html')
        
@authentication_decorator
def mitre_top6(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top6.html')
        
@authentication_decorator
def mitre_top7(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top7.html')
        
@authentication_decorator
def mitre_top8(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top8.html')
        
@authentication_decorator
def mitre_top9(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top9.html')
        
@authentication_decorator
def mitre_top10(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top10.html')
        
@authentication_decorator
def mitre_top11(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top11.html')
        
@authentication_decorator
def mitre_top12(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top12.html')
        
@authentication_decorator
def mitre_top13(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top13.html')
        
@authentication_decorator
def mitre_top14(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top14.html')

@authentication_decorator
def mitre_top15(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top15.html')

@authentication_decorator
def mitre_top16(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top16.html')

@authentication_decorator
def mitre_top17(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top17.html')

@authentication_decorator
def mitre_top18(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top18.html')

@authentication_decorator
def mitre_top19(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top19.html')


@authentication_decorator
def mitre_top20(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top20.html')


@authentication_decorator
def mitre_top21(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top21.html')


@authentication_decorator
def mitre_top22(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top22.html')


@authentication_decorator
def mitre_top23(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top23.html')


@authentication_decorator
def mitre_top24(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top24.html')

@authentication_decorator
def mitre_top25(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top25.html')

@authentication_decorator
def csrf_lab_login(request):
    if request.method == 'GET':
        return render(request, 'mitre/csrf_lab_login.html')
    elif request.method == 'POST':
        password = request.POST.get('password')
        username = request.POST.get('username')
        password = md5(password.encode()).hexdigest()
        User = CSRF_user_tbl.objects.filter(username=username, password=password)
        if User:
            payload ={
                'username': username,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=300),
                'iat': datetime.datetime.utcnow()
            }
            cookie = jwt.encode(payload, _get_jwt_secret(), algorithm='HS256')
            response = redirect("/mitre/9/lab/transaction")
            response.set_cookie('auth_cookiee', cookie)
            return response
        else :
            return redirect('/mitre/9/lab/login')

@authentication_decorator
@csrf_exempt
def csrf_transfer_monei(request):
    if request.method == 'GET':
        try:
            cookie = request.COOKIES['auth_cookiee']
            payload = jwt.decode(cookie, _get_jwt_secret(), algorithms=['HS256'])
            username = payload['username']
            User = CSRF_user_tbl.objects.filter(username=username)
            if not User:
                redirect('/mitre/9/lab/login')
            return render(request, 'mitre/csrf_dashboard.html', {'balance': User[0].balance})
        except:
            return redirect('/mitre/9/lab/login')

def csrf_transfer_monei_api(request,recipent,amount):
    if request.method == "GET":
        cookie = request.COOKIES['auth_cookiee']
        payload = jwt.decode(cookie, _get_jwt_secret(), algorithms=['HS256'])
        username = payload['username']
        User = CSRF_user_tbl.objects.filter(username=username)
        if not User:
            return redirect('/mitre/9/lab/login')
        if int(amount) > 0:
            if int(amount) <= User[0].balance:
                recipent = CSRF_user_tbl.objects.filter(username=recipent)
                if recipent:
                    recipent = recipent[0]
                    recipent.balance = recipent.balance + int(amount)
                    recipent.save()
                    User[0].balance = User[0].balance - int(amount)
                    User[0].save()
        return redirect('/mitre/9/lab/transaction') 
    else:
        return redirect ('/mitre/9/lab/transaction')


# @authentication_decorator
@csrf_exempt
def mitre_lab_25_api(request):
    if request.method == "POST":
        expression = request.POST.get('expression')
        try:
            result = _safe_math_expression(expression)
        except (ValueError, TypeError, ZeroDivisionError, OverflowError, RecursionError):
            return JsonResponse({'error': 'Invalid expression'}, status=400)
        return JsonResponse({'result': result})
    else:
        return redirect('/mitre/25/lab/')


@authentication_decorator
def mitre_lab_25(request):
    return render(request, 'mitre/mitre_lab_25.html')

@authentication_decorator
def mitre_lab_17(request):
    return render(request, 'mitre/mitre_lab_17.html')


@csrf_exempt
def mitre_lab_17_api(request):
    if request.method == "POST":
        ip = request.POST.get('ip', '').strip()
        if not _is_safe_nmap_target(ip):
            return JsonResponse({'error': 'Invalid target'}, status=400)
        res, err = _run_nmap(ip)
        res = res.decode()
        err = err.decode()
        pattern = "STATE SERVICE.*\\n\\n"
        matches = re.findall(pattern, res, re.DOTALL)
        ports = matches[0][14:-2].split('\n') if matches else []
        return JsonResponse({'raw_res': str(res), 'raw_err': str(err), 'ports': ports})