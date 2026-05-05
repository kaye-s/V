from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0002_alter_user_table'),
    ]

    operations = [
        migrations.AddField(
            model_name='codesubmission',
            name='report_data',
            field=models.JSONField(blank=True, null=True),
        ),
    ]