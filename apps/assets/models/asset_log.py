# -*- coding: utf-8 -*-
"""
author : '陈日志'
date : 2018/5/18
"""

import uuid

from django.db import models
from django.utils.translation import ugettext_lazy as _

__all__ = ['AssetLog']


class AssetLog(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True)
    asset = models.ForeignKey("assets.Asset", null=True, blank=True, verbose_name=_("Asset Log"))
    content = models.CharField(max_length=1024, verbose_name="Content")
    date_created = models.DateTimeField(auto_now_add=True, null=True, blank=True, verbose_name=_('Date created'))

