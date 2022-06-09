from queue import Queue
import datetime
import httpx
import json
import sqlalchemy as s
import pandas as pd
import time

# from augur import dbmodels


class OauthKeyManager():
    def __init__(self, config, db_engine, logger):

        self.db_conn = db_engine
        self.logger = logger

        print("Initializing Oauth key manager")

        self.fresh_key_cutoff = 0

        # create a list of oauth keys
        config_key = config['key_database']
        oauth_keys = get_list_of_oauth_keys(self.db_conn, config_key)

        fresh_keys_list = []
        depleted_keys_list = []

        # define httpx client for making requests to api        
        with httpx.Client() as client:

            # loop throuh each key in the list and get the rate_limit and seconds_to_reset
            # then add them either the fresh keys or depleted keys based on the rate_limit
            for oauth in oauth_keys:

                # gets the data for the key
                # key_data has a strucutre of
                """
                Data has this structure
                key_data = {
                    'oauth_id': <oauth_id>,
                    'access_token': <oauth_key,
                    'rate_limit': <requests_remaining>,
                    'seconds_to_reset': <seconds_till_rate_limit_is_replenished>
                }
                """
                key_data = get_oauth_key_data(client, oauth)

                # this makes sure that keys with bad credentials are not used
                if key_data is None:
                    continue

                
                if key_data["rate_limit"] >= self.fresh_key_cutoff:
                    # add key to the fresh keys list
                    fresh_keys_list.append(key_data)
                else:
                    # add it to the depleted keys list
                    depleted_keys_list.append(key_data)

        self.fresh_keys = Queue(maxsize=30)
        self.depleted_keys = []

        # sort the fresh keys by rate_limit from smallest to largeset so that the keys with the least requests get used first
        # the sorting order here is determined by the values that calculate_oauth_sorting_weight returns
        sorted_fresh_keys = sorted(
            fresh_keys_list, key=calculate_oauth_sorting_weight)

        # add the keys to the queue
        for key in sorted_fresh_keys:
            self.fresh_keys.put(key)
        
        sorted_depleted_keys = sorted(
            depleted_keys_list, key=lambda k: k["seconds_to_reset"])

        for key in sorted_depleted_keys:
            self.depleted_keys.append(key)
    
    # mehtod to obtain a new key when one runs out
    def get_key(self, first_key=False):

        if not first_key:
            self.mark_as_depleted()

        while self.fresh_keys.empty() is True:
            
            self.replenish_fresh_keys()

            if self.fresh_keys.empty() is False:
                break

            print("Sleeping for 60 seconds to wait for new keys")
            time.sleep(60)

        first_key_data = list(self.fresh_keys.queue)[0]

        print(first_key_data["rate_limit"])

        return first_key_data["access_token"]

    # helper method to move a key from fresh to depleted
    def mark_as_depleted(self):
        
        # removes key from fresh key queue
        depleted_key = self.fresh_keys.get()

        # adds it to the depleted keys
        self.depleted_keys.append(depleted_key)

    # method that checks the depleted keys to see if they have been reset
    def replenish_fresh_keys(self):

        print("Checking for keys that are replenished now")

        with httpx.Client() as client:
            count = 0
            for key in self.depleted_keys:

                # get the data for the keys
                key_data = get_oauth_key_data(client, key)

                # if the key meets the rate limit cutoff then add it to the fresh keys queue and delelte it from the depleted keys list
                if key_data["rate_limit"] >= self.fresh_key_cutoff:
                    self.fresh_keys.put(key)
                    del key
                    count += 1

            print(f"Found {count} keys that were replenished")


def calculate_oauth_sorting_weight(value):

    return (value["rate_limit"] + (value["seconds_to_reset"] * 0.694)) / 2


################################################################################

# Helper functions relating to oauth keys


def get_list_of_oauth_keys(operations_db_conn, config_key):

    oauthSQL = s.sql.text(f"""
            SELECT * FROM augur_operations.worker_oauth WHERE access_token <> '{config_key}' and platform = 'github'
            """)

    oauth_keys_list = [{'oauth_id': 0, 'access_token': config_key}] + json.loads(
        pd.read_sql(oauthSQL, operations_db_conn, params={}).to_json(orient="records"))

    return oauth_keys_list


def get_oauth_key_data(client, oauth_key_data):

    # this endpoint allows us to check the rate limit, but it does not use one of our 5000 requests
    url = "https://api.github.com/rate_limit"

    headers = {'Authorization': f'token {oauth_key_data["access_token"]}'}

    response = client.request(
        method="GET", url=url, headers=headers, timeout=180)

    data = response.json()

    try:
        if data["message"] == "Bad credentials":
            return None
    except KeyError:
        pass

    rate_limit_data = data["resources"]["core"]

    seconds_to_reset = (
        datetime.datetime.fromtimestamp(
            int(
                rate_limit_data["reset"])
        ) - datetime.datetime.now()
    ).total_seconds()

    key_data = {
        'access_token': oauth_key_data['access_token'],
        'rate_limit': int(rate_limit_data["remaining"]),
        'seconds_to_reset': seconds_to_reset
    }

    return key_data

################################################################################

# Main function to test program

def main():
    # url = "https://api.github.com/repos/chaoss/augur/issues/events?per_page=50&page=5"
    config = '../augur.config.json'

    key_manager = OauthKeyManager(config)

    my_key = key_manager.get_key()

    print(my_key)




if __name__ == '__main__':
    # This code won't run if this file is imported.
    main()