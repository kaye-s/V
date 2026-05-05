# Generated manually for OpenAI usage totals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0004_codesubmission_report_title"),
    ]

    operations = [
        migrations.AddField(
            model_name="user",
            name="total_llm_prompt_tokens",
            field=models.BigIntegerField(default=0),
        ),
        migrations.AddField(
            model_name="user",
            name="total_llm_completion_tokens",
            field=models.BigIntegerField(default=0),
        ),
    ]
