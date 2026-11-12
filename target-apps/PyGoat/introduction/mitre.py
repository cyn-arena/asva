import ast
import datetime
import operator
import re
import shlex
import subprocess
from hashlib import md5

import jwt
from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt

from .models import CSRF_user_tbl
from .views import authentication_decorator

# import os

## Mitre top1 | CWE:787

# target zone
FLAG = "NOT_SUPPOSED_TO_BE_ACCESSED"

# target zone end

_MAX_EXPRESSION_LENGTH = 512
_MAX_EXPONENT = 1000
_SAFE_NMAP_TARGET_RE = re.compile(r'^(?![.-])[A-Za-z0-9._:/-]{1,253}$')

_ALLOWED_BIN_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}

_ALLOWED_UNARY_OPS = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
}


def _eval_ast_node(node):
    if isinstance(node, ast.Expression):
        return _eval_ast_node(node.body)

    if isinstance(node, ast.Constant):
        value = node.value
    elif hasattr(ast, 'Num') and isinstance(node, ast.Num):
        value = node.n
    else:
        value = None

    if value is not None:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError('Invalid expression')
        return value

    if isinstance(node, ast.BinOp):
        op_type = type(node.op)
        if op_type not in _ALLOWED_BIN_OPS:
            raise ValueError('Invalid expression')
        left = _eval_ast_node(node.left)
        right = _eval_ast_node(node.right)
        if op_type is ast.Pow:
            if not isinstance(right, (int, float)):
                raise ValueError('Invalid expression')
            if abs(right) > _MAX_EXPONENT:
                raise ValueError('Invalid expression')
            if isinstance(left, (int, float)) and abs(left) > 10 ** 9 and right > 10:
                raise ValueError('Invalid expression')
        result = _ALLOWED_BIN_OPS[op_type](left, right)
        if isinstance(result, complex):
            raise ValueError('Invalid expression')
        return result

    if isinstance(node, ast.UnaryOp):
        op_type = type(node.op)
        if op_type not in _ALLOWED_UNARY_OPS:
            raise ValueError('Invalid expression')
        return _ALLOWED_UNARY_OPS[op_type](_eval_ast_node(node.operand))

    raise ValueError('Invalid expression')


def _safe_math_expression(expression):
    if not isinstance(expression, str):
        raise ValueError('Invalid expression')
    expression = expression.strip()
    if not expression or len(expression) > _MAX_EXPRESSION_LENGTH:
        raise ValueError('Invalid expression')
    try:
        parsed = ast.parse(expression, mode='eval')
        return _eval_ast_node(parsed)
    except (SyntaxError, TypeError, OverflowError, RecursionError):
        raise ValueError('Invalid expression')


def _is_safe_nmap_target(target):
    if not isinstance(target, str):
        return False
    target = target.strip()
    return bool(target and _SAFE_NMAP_TARGET_RE.fullmatch(target))


def _run_nmap(target):
    try:
        result = subprocess.run(
            ["nmap", target],
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
        return result.stdout, result.stderr
    except FileNotFoundError:
        return b'', b'nmap: command not found\n'
    except subprocess.TimeoutExpired:
        return b'', b'nmap: command timed out\n'


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
            payload = {
                'username': username,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=300),
                'iat': datetime.datetime.utcnow()
            }
            cookie = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
            response = redirect("/mitre/9/lab/transaction")
            response.set_cookie('auth_cookiee', cookie)
            return response
        else:
            return redirect('/mitre/9/lab/login')

@authentication_decorator
@csrf_exempt
def csrf_transfer_monei(request):
    if request.method == 'GET':
        try:
            cookie = request.COOKIES['auth_cookiee']
            payload = jwt.decode(cookie, settings.SECRET_KEY, algorithms=['HS256'])
            username = payload['username']
            User = CSRF_user_tbl.objects.filter(username=username)
            if not User:
                return redirect('/mitre/9/lab/login')
            return render(request, 'mitre/csrf_dashboard.html', {'balance': User[0].balance})
        except (KeyError, jwt.PyJWTError):
            return redirect('/mitre/9/lab/login')

def csrf_transfer_monei_api(request, recipent, amount):
    if request.method == "GET":
        try:
            cookie = request.COOKIES['auth_cookiee']
            payload = jwt.decode(cookie, settings.SECRET_KEY, algorithms=['HS256'])
            username = payload['username']
        except (KeyError, jwt.PyJWTError):
            return redirect('/mitre/9/lab/login')

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
        return redirect('/mitre/9/lab/transaction')


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

def command_out(command):
    if isinstance(command, str):
        command = shlex.split(command)
    if not command:
        return b'', b''
    result = subprocess.run(
        command,
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return result.stdout, result.stderr


@csrf_exempt
def mitre_lab_17_api(request):
    if request.method == "POST":
        ip = request.POST.get('ip', '').strip()
        if not _is_safe_nmap_target(ip):
            return JsonResponse({'error': 'Invalid target'}, status=400)
        res, err = _run_nmap(ip)
        res = res.decode(errors='replace')
        err = err.decode(errors='replace')
        pattern = r"STATE SERVICE.*\n\n"
        matches = re.findall(pattern, res, re.DOTALL)
        ports = matches[0][14:-2].split('\n') if matches else []
        return JsonResponse({'raw_res': str(res), 'raw_err': str(err), 'ports': ports})
    else:
        return redirect('/mitre/17/lab/')