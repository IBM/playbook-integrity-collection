
import os
import tempfile
import gnupg
import ansible_collections.playbook.integrity.plugins.module_utils.common as common


class Signer:
    def __init__(self, params):
        self.pwd = params.get("pwd", "")
        self.type = params.get("type", "")
        self.target = common.validate_path(self.pwd, params.get("target", ""))
        self.signature_type = params.get("signature_type", "gpg")
        self.private_key = params.get("private_key", "")
        if self.private_key != "":
            self.private_key = common.validate_path(self.pwd, self.private_key)
        self.keyless_signer_id = params.get("keyless_signer_id", "")

    def sign(self):
        result = {}
        if self.type == common.TYPE_PLAYBOOK:
            result = self.sign_playbook()
        else:
            raise ValueError("type must be one of [{}]".format([common.TYPE_PLAYBOOK]))
        return result

    def sign_playbook(self):
        result = {"failed": False}
        digester = common.Digester(self.target)
        result["digest_result"] = digester.gen()
        if result["digest_result"]["returncode"] != 0:
            result["failed"] = True
            return result

        if self.signature_type == common.SIGNATURE_TYPE_GPG:
            sig_file = os.path.join(self.target, common.SIGNATURE_FILENAME_GPG)
            if os.path.exists(sig_file):
                os.remove(sig_file) # remove privious signature before signing
            result["sign_result"] = self.sign_gpg(self.target, common.DIGEST_FILENAME, common.SIGNATURE_FILENAME_GPG, self.private_key)
        elif self.signature_type in [common.SIGNATURE_TYPE_SIGSTORE, common.SIGNATURE_TYPE_SIGSTORE_KEYLESS]:
            keyless = True if self.signature_type == common.SIGNATURE_TYPE_SIGSTORE_KEYLESS else False
            type = common.SIGSTORE_TARGET_TYPE_FILE
            result["sign_result"] = self.sign_sigstore(self.target, common.DIGEST_FILENAME, common.SIGNATURE_FILENAME_SIGSTORE, private_key=self.private_key, keyless=keyless, target_type=type)
        else:
            raise ValueError("this signature type is not supported: {}".format(self.signature_type))
        # set overall result
        if result["sign_result"].get("failed", True):
            result["failed"] = True
        return result

    def sign_gpg(self, path, msgfile, sigfile, private_key):
        use_gpg_default_key = False
        if private_key == "":
            use_gpg_default_key = True

        if not os.path.exists(path):
            raise ValueError("the directory \"{}\" does not exists".format(path))

        sigpath = os.path.join(path, sigfile)
        msgpath = os.path.join(path, msgfile)
        result = None
        if use_gpg_default_key:
            gpg = gnupg.GPG()
            result = gpg.sign_file(file=open(msgpath, "rb"), detach=True, output=sigpath)
        else:
            # use a temp dir as gnupg home to disable default GPG keyrings
            with tempfile.TemporaryDirectory() as temp_dir:
                gpg = gnupg.GPG(gnupghome=temp_dir)
                try:
                    gpg.import_keys(open(private_key, "r").read())
                except:
                    try:
                        gpg.import_keys(open(private_key, "rb").read())
                    except:
                        raise
                result = gpg.sign_file(file=open(msgpath, "rb"), detach=True, output=sigpath)
        failed = result.returncode != 0
        return {"failed": failed, "returncode": result.returncode, "stderr": result.stderr}

    def sign_sigstore(self, path, msgfile, sigfile, private_key="", keyless=False, target_type=common.SIGSTORE_TARGET_TYPE_FILE):
        result = None
        if target_type == common.SIGSTORE_TARGET_TYPE_FILE:
            result = self.sign_sigstore_file(path, msgfile, sigfile, private_key, keyless)
        else:
            raise ValueError("this target type \"{}\" is not supported for sigstore signing".format(target_type))
        return result
    
    def sign_sigstore_file(self, path, msgfile, sigfile, private_key="", keyless=False):
        if not os.path.exists(path):
            raise ValueError("the directory \"{}\" does not exists".format(path))
        
        cosign_cmd = common.get_cosign_path()
        output_option = "--output-signature {}".format(sigfile)
        experimental_option=""
        key_option = ""
        idtoken_option = ""
        if keyless:
            experimental_option = "COSIGN_EXPERIMENTAL=1"
            idtoken_option = "--identity-token {}".format(self.keyless_signer_id)
        else:
            key_option = "--key {}".format(private_key)

        cmd = "cd {}; {} {} sign-blob {} {} {} {}".format(path, experimental_option, cosign_cmd, key_option, idtoken_option, output_option, msgfile)
        result = common.execute_command(cmd)
        return result        


