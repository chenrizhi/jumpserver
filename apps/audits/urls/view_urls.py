# ~*~ coding: utf-8 ~*~
from __future__ import unicode_literals


from django.conf.urls import url
from .. import views

__all__ = ["urlpatterns"]

app_name = "audits"

urlpatterns = [
    url(r'^ftp-log/$', views.FTPLogListView.as_view(), name='ftp-log-list'),
    url(r'^ntx-password-decode-log/$', views.NTXPasswordDecodeLogListView.as_view(), name='ntx-password-decode-log-list'),
]
