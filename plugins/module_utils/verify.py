
import os
import base64
import traceback
import requests
import hashlib
import simplejson as json
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import ansible_collections.playbook.integrity.plugins.module_utils.common as common


REKOR_URL = "https://rekor.sigstore.dev"

REKOR_API_HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}

class Verifier:
    def __init__(self, params):
        self.type = params.get("type", "")
        self.target = params.get("target", "")
        if self.target.startswith("~/"):
            self.target = os.path.expanduser(self.target)
        self.signature_type = params.get("signature_type", "gpg")
        self.public_key = params.get("public_key", "")
        if self.public_key.startswith("~/"):
            self.public_key = os.path.expanduser(self.public_key)
        self.keyless_signer_id = params.get("keyless_signer_id", "")

    def verify(self):
        result = {}
        if self.type == common.TYPE_PLAYBOOK:
            result = self.verify_playbook()
        else:
            raise ValueError("type must be one of [{}]".format([common.TYPE_PLAYBOOK]))
        return result

    def verify_playbook(self):
        result = {"failed": False}
        digester = common.Digester(self.target)
        result["digest_result"] = digester.check()
        if result["digest_result"]["returncode"] != 0:
            result["failed"] = True
            return result

        if self.signature_type == common.SIGNATURE_TYPE_GPG:
            result["verify_result"] = self.verify_gpg(self.target, common.SIGNATURE_FILENAME_GPG, common.DIGEST_FILENAME, self.public_key)
        elif self.signature_type in [common.SIGNATURE_TYPE_SIGSTORE, common.SIGNATURE_TYPE_SIGSTORE_KEYLESS]:
            keyless = True if self.signature_type == common.SIGNATURE_TYPE_SIGSTORE_KEYLESS else False
            type = common.SIGSTORE_TARGET_TYPE_FILE
            result["verify_result"] = self.verify_sigstore(self.target, target_type=type, keyless=keyless)
        else:
            raise ValueError("this signature type is not supported: {}".format(self.signature_type))
        if result["verify_result"]["returncode"] != 0:
            result["failed"] = True
            return result

        return result

    def verify_gpg(self, path, sigfile, msgfile, publickey=""):
        if not os.path.exists(path):
            raise ValueError("the directory \"{}\" does not exists".format(path))

        if not os.path.exists(os.path.join(path, sigfile)):
            raise ValueError("signature file \"{}\" does not exists in path \"{}\"".format(sigfile, path))
        
        gpghome_option = ""
        keyring_option = ""
        if publickey != "":
            try:
                os.makedirs(common.TMP_GNUPG_HOME_DIR)
            except Exception:
                pass
            gpghome_option = "GNUPGHOME={}".format(common.TMP_GNUPG_HOME_DIR)
            keyring_option = "--no-default-keyring --keyring {}".format(publickey)
        cmd = "cd {}; {} gpg --verify {} {} {}".format(path, gpghome_option, keyring_option, sigfile, msgfile)
        result = common.execute_command(cmd)
        return result

    def verify_sigstore(self, target, target_type=common.SIGSTORE_TARGET_TYPE_FILE, keyless=False):
        result = None
        if target_type == common.SIGSTORE_TARGET_TYPE_FILE:
            result = self.verify_sigstore_file(self.target, keyless=keyless, msgfile=common.DIGEST_FILENAME, sigfile=common.SIGNATURE_FILENAME_SIGSTORE)
        else:
            raise ValueError("this target type \"{}\" is not supported for sigstore signing".format(target_type))
        return result

    def verify_sigstore_file(self, path, keyless=False, msgfile=common.DIGEST_FILENAME, sigfile=common.SIGNATURE_FILENAME_SIGSTORE):
        if not os.path.exists(path):
            raise ValueError("the directory \"{}\" does not exists".format(path))

        if not os.path.exists(os.path.join(path, sigfile)):
            raise ValueError("signature file \"{}\" does not exists in path \"{}\"".format(sigfile, path))

        msgpath = os.path.join(path, msgfile)
        sigpath = os.path.join(path, sigfile)
        result = verify_cosign_signature(sigpath, msgpath, self.public_key, keyless)
        return result

# This should be replaced with cosign python module once it is ready
def verify_cosign_signature(sigpath, msgpath, pubkeypath, keyless):
    result = {}
    msgdata = None
    with open(msgpath, 'rb') as msg_in:
        msgdata = msg_in.read()
    sigdata = None
    with open(sigpath, 'rb') as sig_in:
        sigdata = sig_in.read()
        sigdata = base64.b64decode(sigdata)

    public_key = None
    if keyless:
        hash = hashlib.sha256(msgdata).hexdigest()
        rekord_data = fetch_rekord(hash)
        b64encoded_sigdata_in_rekord = rekord_data.get("spec", {}).get("signature", {}).get("content", "")
        sigdata_in_rekord = base64.b64decode(b64encoded_sigdata_in_rekord)
        if sigdata_in_rekord != sigdata:
            result["returncode"] = 1
            result["stderr"] = "the signature is different from the one in rekor server"
            return result
        b64encoded_cert_pembytes = rekord_data.get("spec", {}).get("signature", {}).get("publicKey", {}).get("content", "")
        cert_pembytes = base64.b64decode(b64encoded_cert_pembytes)
        certificate = x509.load_pem_x509_certificate(cert_pembytes)
        public_key = certificate.public_key()
    else:
        pemlines = None
        with open(pubkeypath, 'rb') as pem_in:
            pemlines = pem_in.read()
        public_key = load_pem_public_key(pemlines)
    
    try:
        public_key.verify(sigdata, msgdata, ec.ECDSA(hashes.SHA256()))
        result["returncode"] = 0
        result["stdout"] = "the signature has been verified by sigstore python module (a sample module is used here at this moment)"
    except Exception:
        result["returncode"] = 1
        result["stdout"] = "public key type is {}, rekord data: {}".format(type(public_key), json.dumps(rekord_data))
        result["stderr"] = traceback.format_exc()
    return result

# This should be replaced with cosign python module once it is ready
def fetch_rekord(hash):
    rekord_data = None
    rekord_resp = None
    rekor_payload_search = {
        "hash": f"sha256:{hash}",
    }
    payload = json.dumps(rekor_payload_search)
    search_resp = requests.post(f"{REKOR_URL}/api/v1/index/retrieve", data=payload,  headers=REKOR_API_HEADERS)
    uuids = json.loads(search_resp.content)
    uuid = None
    if len(uuids) > 0:
        uuid = uuids[0]
    rekord_resp = requests.get(f"{REKOR_URL}/api/v1/log/entries/{uuid}",  headers=REKOR_API_HEADERS)
    if rekord_resp is None:
        return None
    
    rekord_resp_data = json.loads(rekord_resp.content)
    b64encoded_rekord = rekord_resp_data[uuid]["body"]
    rekord_data = json.loads(base64.b64decode(b64encoded_rekord))
    return rekord_data
