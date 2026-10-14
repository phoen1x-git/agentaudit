"""Legacy HTTP surface, kept around for the internal admin panel.

Deliberately vulnerable sample code for the scanner demo. Do not deploy.
"""
from __future__ import annotations

from flask import Flask, request

app = Flask(__name__)


@app.post("/evaluate")
def evaluate():
    """Evaluate an expression supplied by the caller."""
    return {"value": eval(request.form["code"])}


@app.post("/total")
def total():
    """Sum the numbers in the posted JSON body."""
    numbers = request.get_json().get("numbers", [])
    return {"total": sum(numbers)}
