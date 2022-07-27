
import os
import tempfile
import gnupg
import ansible_collections.playbook.integrity.plugins.module_utils.common as common


class Verifier:
    def __init__(self, params):
        self.pwd = params.get("pwd", "")
        self.type = params.get("type", "")
        self.target = params.get("target", "")
        self.target = common.validate_path(self.pwd, params.get("target", ""))
        self.signature_type = params.get("signature_type", "gpg")
        self.public_key = params.get("public_key", "")
        if self.public_key != "":
            self.public_key = common.validate_path(self.pwd, self.public_key)
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
            result["verify_result"] = self.verify_gpg(self.target, common.DIGEST_FILENAME, common.SIGNATURE_FILENAME_GPG, self.public_key)
        elif self.signature_type in [common.SIGNATURE_TYPE_SIGSTORE, common.SIGNATURE_TYPE_SIGSTORE_KEYLESS]:
            keyless = True if self.signature_type == common.SIGNATURE_TYPE_SIGSTORE_KEYLESS else False
            type = common.SIGSTORE_TARGET_TYPE_FILE
            result["verify_result"] = self.verify_sigstore(self.target, common.DIGEST_FILENAME, common.SIGNATURE_FILENAME_SIGSTORE, self.public_key, keyless, type)
        else:
            raise ValueError("this signature type is not supported: {}".format(self.signature_type))
        # set overall result
        if result["verify_result"].get("failed", True):
            result["failed"] = True
        return result

    def verify_gpg(self, path, msgfile, sigfile, public_key):
        use_gpg_default_key = False
        if self.public_key == "":
            use_gpg_default_key = True

        if not os.path.exists(path):
            raise ValueError("the directory \"{}\" does not exists".format(path))

        if not os.path.exists(os.path.join(path, sigfile)):
            raise ValueError("signature file \"{}\" does not exists in path \"{}\"".format(sigfile, path))
        
        sigpath = os.path.join(path, sigfile)
        msgpath = os.path.join(path, msgfile)
        result = None
        if use_gpg_default_key:
            gpg = gnupg.GPG()
            result = gpg.verify_file(file=open(sigpath, "rb"), data_filename=msgpath)
        else:
            with tempfile.TemporaryDirectory() as dname:
                gpg = gnupg.GPG(gnupghome=dname, keyring=self.public_key)
                try:
                    gpg.import_keys(open(public_key, "r").read())
                except:
                    try:
                        gpg.import_keys(open(public_key, "rb").read())
                    except:
                        raise
                result = gpg.verify_file(file=open(sigpath, "rb"), data_filename=msgpath)
        failed = result.returncode != 0
        return {"failed": failed, "returncode": result.returncode, "stderr": result.stderr}

    def verify_sigstore(self, path, msgfile, sigfile, public_key="", keyless=False, target_type=common.SIGSTORE_TARGET_TYPE_FILE):
        result = None
        if target_type == common.SIGSTORE_TARGET_TYPE_FILE:
            result = self.verify_sigstore_file(path, msgfile, sigfile, public_key, keyless)
        else:
            raise ValueError("this target type \"{}\" is not supported for sigstore signing".format(target_type))
        return result

    def verify_sigstore_file(self, path, msgfile, sigfile, public_key="", keyless=False):
        if not os.path.exists(path):
            raise ValueError("the directory \"{}\" does not exists".format(path))

        if not os.path.exists(os.path.join(path, sigfile)):
            raise ValueError("signature file \"{}\" does not exists in path \"{}\"".format(sigfile, path))
        
        cosign_cmd = common.get_cosign_path()
        experimental_option=""
        key_option = ""
        if keyless:
            experimental_option = "COSIGN_EXPERIMENTAL=1"
        else:
            key_option = "--key {}".format(public_key)
        cmd = "cd {}; {} {} verify-blob {} --signature {} {}".format(path, experimental_option, cosign_cmd, key_option, sigfile, msgfile)
        result = common.execute_command(cmd)
        return result