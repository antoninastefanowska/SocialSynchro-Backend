# -*- coding: utf-8 -*-
# Generated by Django 1.11.15 on 2019-09-27 11:55
from __future__ import unicode_literals

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0005_auto_20190927_1106'),
    ]

    operations = [
        migrations.CreateModel(
            name='RequestCounter',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('request_name', models.CharField(max_length=50, unique=True)),
                ('service_name', models.CharField(max_length=50)),
                ('last_reset_date', models.DateTimeField(default=django.utils.timezone.now)),
                ('reset_window', models.IntegerField()),
                ('limit', models.IntegerField()),
                ('remaining', models.IntegerField()),
                ('reset', models.IntegerField()),
            ],
        ),
        migrations.DeleteModel(
            name='TwitterRateLimits',
        ),
    ]
