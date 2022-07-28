
import os
import platform
import subprocess
import git
import hashlib
import traceback

TYPE_PLAYBOOK = "playbook"

SIGNATURE_TYPE_GPG = "gpg"
SIGNATURE_TYPE_SIGSTORE = "sigstore"
SIGNATURE_TYPE_SIGSTORE_KEYLESS = "sigstore_keyless"

SIGSTORE_TARGET_TYPE_FILE = "file"

SCM_TYPE_GIT = "git"

DIGEST_FILENAME = "sha256sum.txt"
SIGNATURE_FILENAME_GPG = "sha256sum.txt.sig"
SIGNATURE_FILENAME_SIGSTORE = "sha256sum.txt.sig"

CHECKSUM_OK_IDENTIFIER = ": OK"
TMP_COSIGN_PATH = "/tmp/cosign"

class Digester:
    def __init__(self, path):
        self.path = path
        if path.startswith("~/"):
            self.path = os.path.expanduser(path)
        self.type = self.get_scm_type(path)

    # TODO: implement this
    def get_scm_type(self, path):
        return SCM_TYPE_GIT

    def gen(self, path="", filename=DIGEST_FILENAME):
        if path == "":
            path = self.path
        result = None
        if self.type == SCM_TYPE_GIT:
            result = self.gen_git(path, filename)
        else:
            raise ValueError("this SCM type is not supported: {}".format(self.type))
        return result
    
    def check(self, path=""):
        if path == "":
            path = self.path
        result = self.filename_check(path)
        if result["returncode"] != 0:
            return result
        result = self.digest_check(path)
        return result

    def filename_check(self, path):
        digest_file = os.path.join(path, DIGEST_FILENAME)
        if not os.path.exists(digest_file):
            return {
                "returncode": 1,
                "stderr": "No such file or directory: {}".format(digest_file),
            }
        signed_fnames = self.digest_file_to_filename_set(digest_file)
        current_fname_list = self.list_files_git(path, DIGEST_FILENAME)
        current_fnames = set(current_fname_list)
        if signed_fnames != current_fnames:
            added = current_fnames - signed_fnames if len(current_fnames - signed_fnames) > 0 else None
            removed = signed_fnames - current_fnames if len(signed_fnames - current_fnames) > 0 else None
            return {
                "returncode": 1,
                "stderr": "the following files are detected as differences.\nAdded: {}\nRemoved: {}".format(added, removed),
            }
        return {"returncode": 0, "stderr": ""}

    def digest_file_to_filename_set(self, filename):
        s = set()
        lines = []
        with open(filename, "r") as f:
            lines = f.read()
        for line in lines.splitlines():
            items = line.split(" ")
            fname = items[len(items)-1]
            s.add(fname)
        return s

    def digest_check(self, path):
        digest_file = os.path.join(path, DIGEST_FILENAME)
        signed_digest_dict = {}
        with open(digest_file, "r") as file:
            for line in file:
                parts = line.split(" ")
                if len(parts) <= 1:
                    continue
                digest = parts[0]
                fname = " ".join(parts[1:]).replace("\n", "")
                signed_digest_dict[fname] = digest

        filename_list = self.list_files_git(repo_path=path, ignore_prefix=DIGEST_FILENAME)
        current_digest_list = self.calc_digest_for_fname_list(path, filename_list)
        diff_found_files = []
        for line in current_digest_list:
            parts = line.split(" ")
            if len(parts) <= 1:
                continue
            digest = parts[0]
            fname = " ".join(parts[1:])
            signed_digest = signed_digest_dict.get(fname, "__not_found__")
            if digest != signed_digest:
                diff_found_files.append(fname)
        if len(diff_found_files) > 0:
            err_msg = "checksum failed: the following files were changed from the signed state: {}".format(diff_found_files)
            return {"returncode": 1, "stderr": err_msg}
        return {"returncode": 0, "stderr": ""}

    def gen_git(self, repo_path, filename=DIGEST_FILENAME):
        filename_list = self.list_files_git(repo_path=repo_path, ignore_prefix=filename)
        digest_list = self.calc_digest_for_fname_list(repo_path, filename_list)
        try:
            output_path = os.path.join(repo_path, filename)
            with open(output_path, "w") as f:
                f.write("\n".join(digest_list))
        except:
            return {"returncode": 1, "stderr": traceback.format_exc()}
        
        return {"returncode": 0}

    def calc_digest_for_fname_list(self, path, fname_list):
        digest_list = []
        for fname in fname_list:
            fpath = os.path.join(path, fname)
            fdata = open(fpath, "r").read()
            fdigest = hashlib.sha256(fdata.encode()).hexdigest()
            digest_list.append("{} {}".format(fdigest, fname))
        return digest_list

    def list_files_git(self, repo_path, ignore_prefix=DIGEST_FILENAME):
        repo = git.Repo(path=repo_path, search_parent_directories=True)
        commit = repo.commit()
        filename_list = []
        stack = [commit.tree]
        while len(stack) > 0:
            tree = stack.pop()
            for b in tree.blobs:
                # skip symlink
                if os.path.islink(b.path):
                    continue
                # skip digest file and signature file with ignore_prefix
                if os.path.basename(b.path).startswith(ignore_prefix):
                    continue
                # otherwise add the file
                filename_list.append(b.path)
            for subtree in tree.trees:
                stack.append(subtree)
        # sort by filename (to be consistent with sha256sum command)
        filename_list = sorted(filename_list)
        return filename_list

def result_object_to_dict(obj):
    if isinstance(obj, subprocess.CompletedProcess):
        failed = (obj.returncode != 0)
        return dict(
            failed=failed,
            returncode=obj.returncode,
            stdout=obj.stdout,
            stderr=obj.stderr,
        )
    return {}

def execute_command(cmd="", env_params=None, timeout=None):
    env = None
    if env_params is not None:
        env = os.environ.copy()
        env.update(env_params)
    result = subprocess.run(
            cmd, shell=True, env=env, timeout=timeout,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    result = result_object_to_dict(result)
    result["command"] = cmd
    return result


def get_cosign_path():
    cmd1 = "command -v cosign"
    result = execute_command(cmd1)
    if result["returncode"] == 0:
        return "cosign"

    if os.path.exists(TMP_COSIGN_PATH):
        return TMP_COSIGN_PATH

    os_name = platform.system().lower()
    machine = platform.uname().machine
    arch = "unknown"
    if machine == "x86_64":
        arch = "amd64"
    elif machine == "aarch64":
        arch = "arm64"
    elif machine == "ppc64le":
        arch = "ppc64le"
    elif machine == "s390x":
        arch = "s390x"
    else:
        arch = machine

    cmd2 = "curl -sL -o {} https://github.com/sigstore/cosign/releases/download/v1.4.1/cosign-{}-{} && chmod +x {}".format(TMP_COSIGN_PATH, os_name, arch, TMP_COSIGN_PATH)
    result = execute_command(cmd2)
    if result["returncode"] == 0:
        cmd3 = "{} initialize".format(TMP_COSIGN_PATH)
        execute_command(cmd3)
        return TMP_COSIGN_PATH
    else:
        raise ValueError("failed to install cosign command; {}".format(result["stderr"]))

def validate_path(pwd, fpath):
    vaild_path = ""
    if os.path.exists(fpath):
        vaild_path = os.path.abspath(fpath)

    if vaild_path == "" and fpath.startswith("~/"):
        expanded_fpath = os.path.expanduser(fpath)
        if os.path.exists(expanded_fpath):
            vaild_path = expanded_fpath

    if vaild_path == "":
        joined_path = os.path.join(pwd, fpath)
        if os.path.exists(joined_path):
            vaild_path = joined_path

    if vaild_path == "":
        raise ValueError("file not found for the path \"{}\"".format(fpath))
    
    return vaild_path