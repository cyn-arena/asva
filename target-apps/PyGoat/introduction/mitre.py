import ast
import datetime
import ipaddress
import operator
import re
import subprocess
from hashlib import md5

import jwt
from django.conf import settings
from django.http import HttpResponse, HttpResponseBadRequest, JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt

from .models import CSRF_user_tbl
from .views import authentication_decorator

JWT_SECRET = settings.SECRET_KEY
JWT_ALGORITHM = 'HS256'

_MAX_EXPRESSION_LENGTH = 1000
_MAX_POWER_EXPONENT = 100
_MAX_POWER_BASE = 10 ** 6

_SAFE_BIN_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}

_SAFE_UNARY_OPS = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
}

_HOSTNAME_RE = re.compile(
    r'(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*'
)

# import os

## Mitre top1 | CWE:787

# target zone
FLAG = "NOT_SUPPOSED_TO_BE_ACCESSED"

# target zone end


def _calculate_ast_node(node):
    if isinstance(node, ast.Expression):
        return _calculate_ast_node(node.body)
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool) or not isinstance(node.value, (int, float)):
            raise ValueError('Unsupported constant')
        return node.value
    if isinstance(node, ast.BinOp):
        op = _SAFE_BIN_OPS.get(type(node.op))
        if op is None:
            raise ValueError('Unsupported operator')
        left = _calculate_ast_node(node.left)
        right = _calculate_ast_node(node.right)
        if isinstance(node.op, ast.Pow):
            if abs(right) > _MAX_POWER_EXPONENT:
                raise ValueError('Exponent too large')
            if isinstance(left, int) and abs(left) > _MAX_POWER_BASE:
                raise ValueError('Base too large')
        return op(left, right)
    if isinstance(node, ast.UnaryOp):
        op = _SAFE_UNARY_OPS.get(type(node.op))
        if op is None:
            raise ValueError('Unsupported unary operator')
        return op(_calculate_ast_node(node.operand))
    raise ValueError('Unsupported expression')


def calculate_expression(expression):
    if not isinstance(expression, str) or len(expression) > _MAX_EXPRESSION_LENGTH:
        raise ValueError('Invalid expression')
    return _calculate_ast_node(ast.parse(expression, mode='eval'))


def _is_safe_nmap_target(target):
    if not target or target.startswith('-'):
        return False
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return bool(_HOSTNAME_RE.fullmatch(target))


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
            cookie = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
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
            payload = jwt.decode(cookie, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            username = payload['username']
            User = CSRF_user_tbl.objects.filter(username=username)
            if not User:
                return redirect('/mitre/9/lab/login')
            return render(request, 'mitre/csrf_dashboard.html', {'balance': User[0].balance})
        except:
            return redirect('/mitre/9/lab/login')

def csrf_transfer_monei_api(request,recipent,amount):
    if request.method == "GET":
        cookie = request.COOKIES['auth_cookiee']
        payload = jwt.decode(cookie, JWT_SECRET, algorithms=[JWT_ALGORITHM])
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
            result = calculate_expression(expression)
        except (ValueError, SyntaxError, ZeroDivisionError, TypeError, OverflowError):
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
    process = subprocess.Popen(command, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return process.communicate()
    

@csrf_exempt
def mitre_lab_17_api(request):
    if request.method == "POST":
        ip = request.POST.get('ip')
        if not _is_safe_nmap_target(ip):
            return JsonResponse({'error': 'Invalid target'}, status=400)
        command = ["nmap", ip]
        res, err = command_out(command)
        res = res.decode()
        err = err.decode()
        pattern = "STATE SERVICE.*\\n\\n"
        ports = re.findall(pattern, res,re.DOTALL)[0][14:-2].split('\n')
        return JsonResponse({'raw_res': str(res), 'raw_err': str(err), 'ports': ports})