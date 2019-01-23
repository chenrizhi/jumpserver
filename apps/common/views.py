from django.views.generic import TemplateView
from django.shortcuts import render, redirect
from django.contrib import messages
from django.utils.translation import ugettext as _

from .forms import EmailSettingForm, LDAPSettingForm, BasicSettingForm, \
    TerminalSettingForm, SecuritySettingForm
from common.permissions import SuperUserRequiredMixin
from . import utils

import json, re, hashlib, base64
from audits.models import NTXPasswordDecodeLog


class BasicSettingView(SuperUserRequiredMixin, TemplateView):
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
            msg = _("Update setting successfully")
            messages.success(request, msg)
            return redirect('settings:basic-setting')
        else:
            context = self.get_context_data()
            context.update({"form": form})
            return render(request, self.template_name, context)


class EmailSettingView(SuperUserRequiredMixin, TemplateView):
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
            msg = _("Update setting successfully")
            messages.success(request, msg)
            return redirect('settings:email-setting')
        else:
            context = self.get_context_data()
            context.update({"form": form})
            return render(request, self.template_name, context)


class LDAPSettingView(SuperUserRequiredMixin, TemplateView):
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
            msg = _("Update setting successfully")
            messages.success(request, msg)
            return redirect('settings:ldap-setting')
        else:
            context = self.get_context_data()
            context.update({"form": form})
            return render(request, self.template_name, context)


class TerminalSettingView(SuperUserRequiredMixin, TemplateView):
    form_class = TerminalSettingForm
    template_name = "common/terminal_setting.html"

    def get_context_data(self, **kwargs):
        command_storage = utils.get_command_storage_setting()
        replay_storage = utils.get_replay_storage_setting()

        context = {
            'app': _('Settings'),
            'action': _('Terminal setting'),
            'form': self.form_class(),
            'replay_storage': replay_storage,
            'command_storage': command_storage
        }
        kwargs.update(context)
        return super().get_context_data(**kwargs)

    def post(self, request):
        form = self.form_class(request.POST)
        if form.is_valid():
            form.save()
            msg = _("Update setting successfully")
            messages.success(request, msg)
            return redirect('settings:terminal-setting')
        else:
            context = self.get_context_data()
            context.update({"form": form})
            return render(request, self.template_name, context)


class ReplayStorageCreateView(SuperUserRequiredMixin, TemplateView):
    template_name = 'common/replay_storage_create.html'

    def get_context_data(self, **kwargs):
        context = {
            'app': _('Settings'),
            'action': _('Create replay storage')
        }
        kwargs.update(context)
        return super().get_context_data(**kwargs)


class CommandStorageCreateView(SuperUserRequiredMixin, TemplateView):
    template_name = 'common/command_storage_create.html'

    def get_context_data(self, **kwargs):
        context = {
            'app': _('Settings'),
            'action': _('Create command storage')
        }
        kwargs.update(context)
        return super().get_context_data(**kwargs)


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
            pwd = base64.b64encode(sha.encode())[0:_pwdlen(mac)].decode()
            resp['msg'] = pwd
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')
            if x_forwarded_for and x_forwarded_for[0]:
                remote_addr = x_forwarded_for[0]
            else:
                remote_addr = request.META.get('REMOTE_ADDR', '')
            NTXPasswordDecodeLog.objects.create(
                user=request.user.username,
                remote_addr=remote_addr,
                mac=mac,
                Password=pwd,
            )
            return HttpResponse(json.dumps(resp))
			

class SecuritySettingView(AdminUserRequiredMixin, TemplateView):
    form_class = SecuritySettingForm
    template_name = "common/security_setting.html"

    def get_context_data(self, **kwargs):
        context = {
            'app': _('Settings'),
            'action': _('Security setting'),
            'form': self.form_class(),
        }
        kwargs.update(context)
        return super().get_context_data(**kwargs)

    def post(self, request):
        form = self.form_class(request.POST)
        if form.is_valid():
            form.save()
            msg = _("Update setting successfully")
            messages.success(request, msg)
            return redirect('settings:security-setting')
        else:
            context = self.get_context_data()
            context.update({"form": form})
            return render(request, self.template_name, context)
