from flask import Blueprint

# base = Blueprint('base', __name__, url_prefix='/api')
base = Blueprint('base', __name__)
from ..routes import *
