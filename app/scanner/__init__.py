import os
from flask import Flask, render_template
from flask_moment import Moment
from flask_sqlalchemy import SQLAlchemy
from config import config
from flask_cors import CORS

import json
from datetime import datetime, date

JSONEncoder = json.JSONEncoder

class CustomJSONEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%d %H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        else:
            return JSONEncoder.default(self, obj)
        
def create_app(config_name):
    app_backend = Flask(__name__)
    CORS(app_backend)
    #  替换默认的json编码器
    app_backend.json_encoder = CustomJSONEncoder
    app_backend.config.from_object(config[config_name])
    config[config_name].init_app(app_backend)

    moment_backend.init_app(app_backend)
    db_backend.init_app(app_backend)
    return app_backend

# Here, backend means other threads
moment_backend = Moment()
db_backend = SQLAlchemy()
app_backend = create_app(os.getenv('FLASK_CONFIG') or 'default')
