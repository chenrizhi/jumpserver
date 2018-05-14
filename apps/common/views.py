
from django.core.cache import cache
from django.views.generic import TemplateView, View, DetailView
from django.shortcuts import render, redirect, Http404, reverse, HttpResponse
from django.contrib import messages
from django.utils.translation import ugettext as _
from django.conf import settings
import json, re, hashlib, base64

from .forms import EmailSettingForm, LDAPSettingForm, BasicSettingForm, \
    TerminalSettingForm
from .mixins import AdminUserRequiredMixin
from .signals import ldap_auth_enable


class BasicSettingView(AdminUserRequiredMixin, TemplateView):
    form_class = BasicSettingForm
    template_name = "common/basic_setting.html"

    def get_context_data(self, **kwargs):
        context = {
            'app': _('Settings'),
            'action': _('Basic setting'),
            'form': self.form_class(),
        }
        kwargs.update(context)
        return super().get_context_data(**kwargs)

    def post(self, request):
        form = self.form_class(request.POST)
        if form.is_valid():
            form.save()
            msg = _("Update setting successfully, please restart program")
            messages.success(request, msg)
            return redirect('settings:basic-setting')
        else:
            context = self.get_context_data()
            context.update({"form": form})
            return render(request, self.template_name, context)


class EmailSettingView(AdminUserRequiredMixin, TemplateView):
    form_class = EmailSettingForm
    template_name = "common/email_setting.html"

    def get_context_data(self, **kwargs):
        context = {
            'app': _('Settings'),
            'action': _('Email setting'),
            'form': self.form_class(),
        }
        kwargs.update(context)
        return super().get_context_data(**kwargs)

    def post(self, request):
        form = self.form_class(request.POST)
        if form.is_valid():
            form.save()
            msg = _("Update setting successfully, please restart program")
            messages.success(request, msg)
            return redirect('settings:email-setting')
        else:
            context = self.get_context_data()
            context.update({"form": form})
            return render(request, self.template_name, context)


class LDAPSettingView(AdminUserRequiredMixin, TemplateView):
    form_class = LDAPSettingForm
    template_name = "common/ldap_setting.html"

    def get_context_data(self, **kwargs):
        context = {
            'app': _('Settings'),
            'action': _('LDAP setting'),
            'form': self.form_class(),
        }
        kwargs.update(context)
        return super().get_context_data(**kwargs)

    def post(self, request):
        form = self.form_class(request.POST)
        if form.is_valid():
            form.save()
            if "AUTH_LDAP" in form.cleaned_data:
                ldap_auth_enable.send(form.cleaned_data["AUTH_LDAP"])
            msg = _("Update setting successfully, please restart program")
            messages.success(request, msg)
            return redirect('settings:ldap-setting')
        else:
            context = self.get_context_data()
            context.update({"form": form})
            return render(request, self.template_name, context)


class TerminalSettingView(AdminUserRequiredMixin, TemplateView):
    form_class = TerminalSettingForm
    template_name = "common/terminal_setting.html"

    def get_context_data(self, **kwargs):
        command_storage = settings.TERMINAL_COMMAND_STORAGE
        replay_storage = settings.TERMINAL_REPLAY_STORAGE
        context = {
            'app': _('Settings'),
            'action': _('Terminal setting'),
            'form': self.form_class(),
            'replay_storage': replay_storage,
            'command_storage': command_storage,
        }
        kwargs.update(context)
        return super().get_context_data(**kwargs)

    def post(self, request):
        form = self.form_class(request.POST)
        if form.is_valid():
            form.save()
            msg = _("Update setting successfully, please restart program")
            messages.success(request, msg)
            return redirect('settings:terminal-setting')
        else:
            context = self.get_context_data()
            context.update({"form": form})
            return render(request, self.template_name, context)


class ToolsView(TemplateView):
    template_name = "common/tools.html"

    def get_context_data(self, **kwargs):
        context = {
            'app': _('Settings'),
            'action': _('Tools'),
        }
        kwargs.update(context)
        return super().get_context_data(**kwargs)

    def post(self,request):
        print(request.body)
        mac = request.POST.get('mac', '').upper()
        resp = {
            'status': False,
            'msg': '不能为空',
        }
        if not mac:
            return HttpResponse(json.dumps(resp))
        def _pwdlen(mac):
            field = mac.split(':')
            sum = 0
            for f in field:
                sum += int(f,16)
            return sum%9+8
        if not re.match('([0-9A-F]{2}:){5}[0-9A-F]{2}', mac):
            resp['msg'] = '格式错误'
            return HttpResponse(json.dumps(resp))
        else:
            sha = hashlib.sha256((mac+"\n").encode()).hexdigest()
            resp['status'] = True
            resp['msg'] = base64.b64encode(sha.encode())[0:_pwdlen(mac)].decode()
            return HttpResponse(json.dumps(resp))

