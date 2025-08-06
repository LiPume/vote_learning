from django.http import JsonResponse, HttpRequest, HttpResponse
from django.shortcuts import render, redirect

from polls.models import Subject, Teacher , User
from polls.utils import Captcha, gen_random_code, gen_md5_digest
import re

def show_subjects(request):
    subjects = Subject.objects.all().order_by('no')
    return render(request, 'subjects.html', {'subjects': subjects})


def show_teachers(request):
    try:
        sno = int(request.GET.get('sno'))
        teachers = []
        if sno:
            subject = Subject.objects.only('name').get(no=sno)
            teachers = Teacher.objects.filter(subject=subject).order_by('no')
        return render(request, 'teachers.html', {
            'subject': subject,
            'teachers': teachers
        })
    except (ValueError, Subject.DoesNotExist):
        return redirect('/')

def praise_or_criticize(request: HttpRequest) -> HttpResponse:
    if request.session.get('userid'):
        try:
            tno = int(request.GET.get('tno'))
            teacher = Teacher.objects.get(no=tno)
            if request.path.startswith('/praise/'):
                teacher.good_count += 1
                count = teacher.good_count
            else:
                teacher.bad_count += 1
                count = teacher.bad_count
            teacher.save()
            data = {'code': 20000, 'mesg': '投票成功', 'count': count}
        except (ValueError, Teacher.DoesNotExist):
            data = {'code': 20001, 'mesg': '投票失败'}
    else:
        data = {'code': 20002, 'mesg': '请先登录'}
    return JsonResponse(data)



'''
提供验证码
'''
def get_captcha(request: HttpRequest) -> HttpResponse:
    """验证码"""
    captcha_text = gen_random_code()
    request.session['captcha'] = captcha_text
    image_data = Captcha.instance().generate(captcha_text)
    return HttpResponse(image_data, content_type='image/png')

'''
添加渲染登录页面的视图函数：
'''

def login(request: HttpRequest) -> HttpResponse:
    hint = ''
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        # 1. 使用正则表达式验证用户名和密码
        # 这里以一个简单的正则为例：
        # - 用户名：4到20个字母、数字或下划线
        # - 密码：6到20个非空白字符
        username_pattern = re.compile(r'^\w{4,20}$')
        password_pattern = re.compile(r'^\S{6,20}$')

        if not username or not username_pattern.match(username):
            hint = '用户名格式不正确，请输入4-20位字母、数字或下划线'
        elif not password or not password_pattern.match(password):
            hint = '密码格式不正确，请输入6-20位非空白字符'
        else:
            # 2. 如果输入格式正确，再进行数据库查询
            password_md5 = gen_md5_digest(password)
            user = User.objects.filter(username=username, password=password_md5).first()

            if user:
                request.session['userid'] = user.no
                request.session['username'] = user.username
                # 登录成功后，检查是否存在 next 参数
                next_url = request.GET.get('next')
                if next_url:
                    return redirect(next_url)
                else:
                    return redirect('/')  # 如果没有 next 参数，就重定向到首页
            else:
                hint = '用户名或密码错误'

    return render(request, 'login.html', {'hint': hint})

def logout(request):
    """
    注销用户，清空 session 并重定向到登录页面。
    """
    # 1. 清空当前用户的 session
    request.session.flush()

    # 2. 重定向到登录页面
    return redirect('/login/')


def register(request: HttpRequest) -> HttpResponse:
    hint = ''
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        password_again = request.POST.get('password_again')

        # 1. 验证用户输入
        # 用户名正则：4-20位字母、数字或下划线
        username_pattern = re.compile(r'^\w{4,20}$')
        # 密码正则：6-20位非空白字符
        password_pattern = re.compile(r'^\S{6,20}$')

        # 验证码校验
        if not username or not username_pattern.match(username):
            hint = '用户名格式不正确，请输入4-20位字母、数字或下划线'
        # 密码校验
        elif not password or not password_pattern.match(password):
            hint = '密码格式不正确，请输入6-20位非空白字符'
        # 两次密码是否一致
        elif password != password_again:
            hint = '两次输入的密码不一致'
        # 用户名是否已存在
        elif User.objects.filter(username=username).exists():
            hint = '该用户名已被注册'
        else:
            # 2. 所有验证通过，创建新用户
            try:
                # 密码加密
                password_md5 = gen_md5_digest(password)
                # 创建并保存新用户对象
                User.objects.create(username=username, password=password_md5)
                # 注册成功后，可以自动登录并重定向到首页
                # 或者重定向到登录页面
                # 这里选择重定向到登录页面
                return redirect('/login/')
            except Exception as e:
                # 捕获可能的异常，比如数据库写入失败
                hint = f'注册失败，请稍后再试: {e}'

    # 3. 如果是 GET 请求或注册失败，渲染注册页面
    return render(request, 'register.html', {'hint': hint})

