# -*- coding: utf-8 -*-
# Generated by Django 1.11.15 on 2019-09-26 20:29
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0003_auto_20190926_1158'),
    ]

    operations = [
        migrations.AlterField(
            model_name='twitterratelimits',
            name='limit',
            field=models.IntegerField(default=5),
        ),
        migrations.AlterField(
            model_name='twitterratelimits',
            name='remaining',
            field=models.IntegerField(default=5),
        ),
        migrations.AlterField(
            model_name='twitterratelimits',
            name='reset',
            field=models.IntegerField(default=10),
        ),
    ]
