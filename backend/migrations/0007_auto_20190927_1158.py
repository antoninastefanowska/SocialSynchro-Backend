# -*- coding: utf-8 -*-
# Generated by Django 1.11.15 on 2019-09-27 11:58
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0006_auto_20190927_1155'),
    ]

    operations = [
        migrations.AlterField(
            model_name='requestcounter',
            name='limit',
            field=models.IntegerField(null=True),
        ),
        migrations.AlterField(
            model_name='requestcounter',
            name='remaining',
            field=models.IntegerField(null=True),
        ),
        migrations.AlterField(
            model_name='requestcounter',
            name='reset',
            field=models.IntegerField(null=True),
        ),
        migrations.AlterField(
            model_name='requestcounter',
            name='reset_window',
            field=models.IntegerField(null=True),
        ),
    ]
