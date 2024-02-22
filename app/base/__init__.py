from flask import Blueprint

# base = Blueprint('base', __name__, url_prefix='/api')
base = Blueprint('base', __name__)
from ..routes import *
from ..routes import scan, cert
from ..routes import cert_analysis
