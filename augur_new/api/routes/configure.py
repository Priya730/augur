#SPDX-License-Identifier: MIT
"""
Creates routes for user login functionality
"""

import logging
import requests
import json
from sqlalchemy import create_engine
from sqlalchemy import exc as sqlalchemy_exception
from flask import request, Response, jsonify

from augur_db.models import User

logger = logging.getLogger(__name__)


def generate_upgrade_request():
    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/426
    response = jsonify({"status": "SSL Required"})
    response.headers["Upgrade"] = "TLS"
    response.headers["Connection"] = "Upgrade"

    return response, 426


def create_routes(server):

    @server.app.errorhandler(405)
    def unsupported_method(error):
        return jsonify({"status": "Unsupported method"}), 405

    @server.app.route(f"/{server.api_version}/configure/keys", methods=['POST'])
    def configure_keys():
        if not request.is_secure:
            return generate_upgrade_request()

        user = response.args.get("user_id")
        password = response.args.get("password")

        if user is None or password is None:
            # https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/400
            return jsonify({"status": "Missing argument"}), 400

        # TODO database stuff. See pseudocode below

        """
        - SELECT * FROM users WHERE id = user

        - if not result:
            return jsonify({"status": "Invalid user ID"})

        - Hash user's password

        - if not pass_hash == password:
            return jsonify({"status": "invalid password"})

        - return jsonify({"status": "Validated"})
        """

    @server.app.route(f"/{server.api_version}/configure/logs", methods=['POST'])
    def configure_logs_directory():
        if not request.is_secure:
            return generate_upgrade_request()

        user = response.args.get("user_id")
        password = response.args.get("password")

        if user is None or password is None:
            # https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/400
            return jsonify({"status": "Missing argument"}), 400

        # TODO database stuff. See pseudocode below

        user = User(username=name, password=password, email=email)

        db.session.add(user)
        db.commit()

        """
        - SELECT * FROM users WHERE id = user

        - if result:
            return jsonify({"status": "User already exists"})

        - Hash user's password

        - INSERT INTO users VALUES (user, pass_hash)

        - return jsonify({"status": "User created"})
        """

    @server.app.route(f"/{server.api_version}/configure/database_conn", methods=['POST'])
    def configure_db_connection():
        # if not request.is_secure:
        #     return generate_upgrade_request()

        db_string = request.args.get('db_string')

        for i in request.args:
            print(i)
        print(dir(request.args))


        try:

            create_engine(db_string, pre_pool_ping=True)

        except sqlalchemy_exception.ArgumentError as e:

           print(f"Unable to parse url from db conn: {e}")

           return jsonify({"status": "Unable to parse database url"})


        return jsonify({"status": "Valid database url"})


        

        # if user is None or password is None:
        #     # https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/400
        #     return jsonify({"status": "Missing argument"}), 400

        # # TODO database stuff. See pseudocode below

        # user = User(username=name, password=password, email=email)

        # db.session.add(user)
        # db.commit()

        """
        - SELECT * FROM users WHERE id = user

        - if result:
            return jsonify({"status": "User already exists"})

        - Hash user's password

        - INSERT INTO users VALUES (user, pass_hash)

        - return jsonify({"status": "User created"})
        """
