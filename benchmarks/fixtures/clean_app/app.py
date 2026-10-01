"""A clean AI app fixture — should produce no (or near-zero) findings."""
import os
import torch
import yaml

API_KEY = os.environ["OPENAI_API_KEY"]  # from env, not hard-coded


def load_weights(path):
    return torch.load(path, weights_only=True)  # safe


def load_cfg(path):
    with open(path) as fh:
        return yaml.safe_load(fh)  # safe
