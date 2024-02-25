# import os
# from flask import Flask, render_template
# from flask_moment import Moment
# from flask_sqlalchemy import SQLAlchemy
# from config import config
# from flask_cors import CORS

# import json
# from datetime import datetime, date

# JSONEncoder = json.JSONEncoder

# class CustomJSONEncoder(JSONEncoder):
#     def default(self, obj):
#         if isinstance(obj, datetime):
#             return obj.strftime('%Y-%m-%d %H:%M:%S')
#         elif isinstance(obj, date):
#             return obj.strftime('%Y-%m-%d')
#         else:
#             return JSONEncoder.default(self, obj)
        
# def create_app(config_name):
#     app = Flask(__name__)
#     CORS(app)
#     #  替换默认的json编码器
#     app.json_encoder = CustomJSONEncoder
#     app.config.from_object(config[config_name])
#     config[config_name].init_app(app)

#     moment_backend.init_app(app)
#     db.init_app(app)
#     return app

# # Here, backend means other threads
# moment_backend = Moment()
# db = SQLAlchemy()
# app = create_app(os.getenv('FLASK_CONFIG') or 'default')
