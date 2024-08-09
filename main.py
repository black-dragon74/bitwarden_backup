import datetime
import json
import os
import requests
import subprocess
from dotenv import load_dotenv
from enum import Enum

# IMPORTANT: Load env from the file
ENV_FILE = "app.env"
if not os.path.exists(ENV_FILE):
    raise Exception("app.env file not found, please create it in the root directory")

if not load_dotenv(dotenv_path=ENV_FILE):
    raise Exception("Failed to load environment variables from {}".format(ENV_FILE))


class Config:
    CLIENT_ID = os.getenv('HCP_CLIENT_ID')
    CLIENT_SECRET = os.getenv('HCP_CLIENT_SECRET')

    APP_NAME = os.getenv('HCP_APP_NAME')
    ORG_ID = os.getenv('HCP_ORG_ID')
    PROJECT_ID = os.getenv('HCP_PROJECT_ID')

    MASTER_KEY = os.getenv('BW_SECRET_NAME')
    ENC_KEY = os.getenv('FILE_ENCRYPTION_KEY')

    if not all(x is not None for x in [
        CLIENT_ID,
        CLIENT_SECRET,

        APP_NAME,
        ORG_ID,
        PROJECT_ID,

        MASTER_KEY,
        ENC_KEY
    ]):
        raise ValueError('One or more environment variables are not set')


class BWStatus(Enum):
    UNLOCKED = 0
    LOCKED = 1
    UNAUTHENTICATED = 2


class BW:
    def __init__(self, master_key):
        self._master_key = master_key
        self._session_key = None

        self._check_bw_binary()

        # If logged out, error
        if self.status() == BWStatus.UNAUTHENTICATED:
            raise Exception("Not logged in, please login first")

    @staticmethod
    def _check_bw_binary():
        # check if bw binary is installed
        bw_location = subprocess.run(["which", "bw"], capture_output=True)
        if bw_location.returncode != 0:
            raise Exception("bw binary not found")

    @staticmethod
    def _call(*args):
        # call bw binary with args
        output = subprocess.run(["bw", "--raw", *args], capture_output=True)

        # If error, raise an exception
        if output.returncode != 0:
            raise Exception("An exception occurred: ".format(output.stderr.decode("utf-8")))

        # Otherwise, return the output as json
        return output.stdout.decode("utf-8")

    def status(self) -> BWStatus:
        # Get the status of the bitwarden vault
        bw_state = self._call("status")
        bw_state = json.loads(bw_state)

        if bw_state["status"] == "unlocked":
            return BWStatus.UNLOCKED
        elif bw_state["status"] == "locked":
            return BWStatus.LOCKED
        elif bw_state["status"] == "unauthenticated":
            print("You are not authenticated with BitWarden, please login first!")
            return BWStatus.UNAUTHENTICATED
        else:
            raise Exception("Received unknown status from bw: " + bw_state["status"])

    def unlock(self):
        resp = self._call("unlock", "--raw", self._master_key)

        if resp is None or resp == "":
            raise Exception("Failed to unlock vault")

        self._session_key = resp
        os.environ["BW_SESSION"] = self._session_key

        if self.status() == BWStatus.UNLOCKED:
            print("Successfully unlocked vault with session key: {}".format(self._session_key))
        else:
            raise Exception("Failed to unlock vault, invalid status: {}".format(self.status()))

    def lock(self):
        self._call("lock", "--raw")
        os.unsetenv("BW_SESSION")

    def list(self, resource_type):
        out = self._call("list", resource_type, "--raw")

        if out is None or out == "":
            raise Exception("Failed to list {}".format(resource_type))

        return json.loads(out)

    def export(self, resource_type, output_file):
        out = self.list(resource_type)

        with open(output_file, "w") as f:
            f.write(json.dumps(out))

        print("Exported {} to {}".format(resource_type, output_file))
        f.close()


def get_secret() -> [dict]:
    url = "https://api.cloud.hashicorp.com/secrets/2023-06-13/organizations/{}/projects/{}/apps/{}/open".format(
        Config.ORG_ID,
        Config.PROJECT_ID,
        Config.APP_NAME
    )

    access_token = get_access_token()
    headers = {
        "Authorization": "Bearer {}".format(access_token)
    }

    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        raise Exception("Failed with status code {}".format(response.status_code))

    secrets = response.json().get("secrets")
    if secrets is None:
        raise Exception("Could not extract secrets from response: {}".format(response.json()))

    return secrets


def get_access_token():
    hcp_auth_url = "https://auth.idp.hashicorp.com/oauth2/token"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    data = {
        "client_id": Config.CLIENT_ID,
        "client_secret": Config.CLIENT_SECRET,
        "grant_type": "client_credentials",
        "audience": "https://api.hashicorp.cloud"
    }

    response = requests.post(hcp_auth_url, headers=headers, data=data)
    access_token = response.json().get("access_token")

    if access_token is None:
        raise Exception("Could not get access token")
    else:
        return access_token


def parse_secret(secrets: dict) -> (str, str):
    master_key = None
    enc_key = None

    for secret in secrets:
        if secret["name"] == Config.MASTER_KEY:
            master_key = secret["version"]["value"]
        elif secret["name"] == Config.ENC_KEY:
            enc_key = secret["version"]["value"]
        else:
            continue

    if master_key is None or enc_key is None:
        raise Exception("Could not find master key or public key")

    return master_key, enc_key


def run():
    # Get secrets from HCP
    master_key, enc_key = parse_secret(
        get_secret()
    )
    out_file = "bw_export_{}.json".format(datetime.datetime.now().strftime("%Y_%m_%d-%H:%M:%S"))

    # Unlock the vault
    bw_cli = BW(master_key)
    bw_cli.unlock()

    # Write the secrets to a file
    bw_cli.export("items", out_file)

    # Encrypt the output file with public_key
    from crypt import process_file
    if process_file("encrypt", out_file, "{}.crypt".format(out_file), enc_key) == 0:
        os.remove(out_file)
        print("Removed unencrypted file")
    else:
        print("Failed to encrypt the file, not removing the original file")


if __name__ == '__main__':
    run()
