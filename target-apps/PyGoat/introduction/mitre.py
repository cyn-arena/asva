import ast
import datetime
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

# import os

JWT_SECRET = settings.SECRET_KEY

_SAFE_BINARY_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}

_SAFE_UNARY_OPERATORS = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
}

_SAFE_COMPARISON_OPERATORS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
}


def _safe_calculate(node):
    if isinstance(node, ast.Expression):
        return _safe_calculate(node.body)
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (int, float, str, bool)) or node.value is None:
            return node.value
        raise ValueError("Unsupported constant")
    if isinstance(node, ast.BinOp):
        operation = _SAFE_BINARY_OPERATORS.get(type(node.op))
        if operation is None:
            raise ValueError("Unsupported binary operator")
        return operation(_safe_calculate(node.left), _safe_calculate(node.right))
    if isinstance(node, ast.UnaryOp):
        operation = _SAFE_UNARY_OPERATORS.get(type(node.op))
        if operation is None:
            raise ValueError("Unsupported unary operator")
        return operation(_safe_calculate(node.operand))
    if isinstance(node, ast.Compare):
        left = _safe_calculate(node.left)
        for operation_node, comparator in zip(node.ops, node.comparators):
            operation = _SAFE_COMPARISON_OPERATORS.get(type(operation_node))
            if operation is None:
                raise ValueError("Unsupported comparison operator")
            right = _safe_calculate(comparator)
            if not operation(left, right):
                return False
            left = right
        return True
    raise ValueError("Unsupported expression")


## Mitre top1 | CWE:787

# target zone
FLAG = "NOT_SUPPOSED_TO_BE_ACCESSED"

# target zone end


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
            cookie = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
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
            payload = jwt.decode(cookie, JWT_SECRET, algorithms=['HS256'])
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
        payload = jwt.decode(cookie, JWT_SECRET, algorithms=['HS256'])
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
            result = _safe_calculate(ast.parse(expression, mode='eval'))
        except (SyntaxError, ValueError, TypeError):
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
        if not ip or ip.startswith('-') or not re.fullmatch(r"[A-Za-z0-9:./\[\]\-]+", ip):
            return JsonResponse({'error': 'Invalid target'}, status=400)
        command = ["nmap", ip]
        res, err = command_out(command)
        res = res.decode()
        err = err.decode()
        pattern = "STATE SERVICE.*\\n\\n"
        ports = re.findall(pattern, res,re.DOTALL)[0][14:-2].split('\n')
        return JsonResponse({'raw_res': str(res), 'raw_err': str(err), 'ports': ports})