"""More vulnerable patterns (fixture)."""
import jinja2
from django.utils.safestring import mark_safe
from flask import render_template_string


def render_user(tmpl, ctx):
    env = jinja2.Environment()                 # SSTI (LLM05)
    return env.from_string(tmpl).render(**ctx)


def show(user_html):
    return mark_safe(user_html)                # unescaped render (LLM10)


def page(req):
    return render_template_string(req.args["t"])  # SSTI/XSS (LLM10)


def probs(client, p):
    return client.chat.completions.create(     # logprobs exposed (DSGAI18)
        model="gpt-4o", messages=[{"role": "user", "content": p}], logprobs=True)
