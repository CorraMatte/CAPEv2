import grp
import json
import os
import pwd
import uuid

from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view
from rest_framework.response import Response

from lib.cuckoo.common.cape_utils import init_yara, log
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.suricatasc import SuricataSC, SuricataCommandException

YARA_BASE_FOLDER = os.path.join(CUCKOO_ROOT, "data", "yara")
YARA_CUSTOM_RULE_FOLDERS = [os.path.join(YARA_BASE_FOLDER, "custom")]
SURICATA_BASE_FOLDER = os.path.join("/", "etc", "suricata", "rules")


@csrf_exempt
@api_view(["POST"])
def upload_yara(request, reload_rule: bool = True):
    try:
        _id = request.data["id"]
        body = request.data["body"]
    except KeyError:
        return Response({"error": True, "error_value": "id or body not set in request"})

    filename = _id + ".yar"

    for folder in YARA_CUSTOM_RULE_FOLDERS:
        full_path = os.path.join(folder, filename)

        with open(full_path, "w") as f:
            f.write(body)

    if reload_rule:
        try:
            init_yara()
        except Exception as e:
            for folder in YARA_CUSTOM_RULE_FOLDERS:
                full_path = os.path.join(folder, filename)
                os.remove(full_path)

            return {"error": True, "error_value": f"Unable to refresh Yara rule due to {e}"}

    return Response({"yara": filename, "error": False})


@csrf_exempt
@api_view(["DELETE"])
def delete_yara(request, _id, reload_rule: bool = True):
    for folder in YARA_CUSTOM_RULE_FOLDERS:
        full_path = os.path.join(folder, f"{_id}.yar")
        try:
            os.remove(full_path)
        except FileNotFoundError:
            return Response({"error_value": "Yara not found", "error": True})

    if reload_rule:
        try:
            init_yara()
        except Exception as e:
            return {"error": True, "error_value": f"Unable to refresh Yara rule due to {e}"}

    return Response({"error": False})


@csrf_exempt
@api_view(["POST"])
def clean_up_yara(request):
    for folder in YARA_CUSTOM_RULE_FOLDERS:
        for f in os.listdir(folder):
            try:
                uuid.UUID(f[:-4])
                os.remove(os.path.join(folder, f))
            except ValueError:
                # Rule is not a custom one
                pass

    try:
        init_yara()
    except Exception as e:
        return {"error": True, "error_value": f"Unable to refresh Yara rule due to {e}"}

    return Response({"error": False})


def update_suricata_rules():
    c = Config("processing")
    suricata_socket_path = c.suricata.get("socket_file")

    suris = SuricataSC(suricata_socket_path)
    suris.connect()
    return suris.send_command("ruleset-reload-nonblocking")


@csrf_exempt
@api_view(["POST"])
def upload_suricata(request, reload_rule: bool = True):
    try:
        _id = request.data["id"]
        body = request.data["body"]
    except KeyError:
        return Response({"error": True, "error_value": "id or body not set in request"})

    filename = _id + ".rules"
    full_path = os.path.join(SURICATA_BASE_FOLDER, filename)

    with open(full_path, "w") as f:
        f.write(body)

    uid = pwd.getpwnam("cape").pw_uid
    gid = grp.getgrnam("suricata").gr_gid

    os.chown(full_path, uid, gid)

    if reload_rule:
        try:
            cmd_out = update_suricata_rules()

            if cmd_out["return"].upper() not in ["NOK", "OK"]:
                raise SuricataCommandException(f"ruleset-reload-nonblocking command return with {cmd_out}")

        except Exception as e:
            os.remove(full_path)
            return {"error": True, "error_value": f"Unable to refresh Suricata rule due to {e}"}

    return Response({"suricata": filename, "error": False})


@csrf_exempt
@api_view(["DELETE"])
def delete_suricata(request, _id, reload_rule: bool = True):
    full_path = os.path.join(SURICATA_BASE_FOLDER, f"{_id}.rules")
    try:
        os.remove(full_path)
    except FileNotFoundError:
        return Response({"error_value": "Suricata not found", "error": True})

    if reload_rule:
        try:
            cmd_out = update_suricata_rules()

            if cmd_out["return"].upper() not in ["NOK", "OK"]:
                raise SuricataCommandException(f"ruleset-reload-nonblocking command return with {cmd_out}")

        except Exception as e:
            return {"error": True, "error_value": f"Unable to refresh Suricata rule due to {e}"}

    return Response({"error": False})


@csrf_exempt
@api_view(["POST"])
def clean_up_suricata(request):
    for f in os.listdir(SURICATA_BASE_FOLDER):
        try:
            uuid.UUID(f[:-4])
            os.remove(os.path.join(SURICATA_BASE_FOLDER, f))
        except ValueError:
            # Rule is not a custom one
            pass

    try:
        cmd_out = update_suricata_rules()

        if cmd_out["return"].upper() not in ["NOK", "OK"]:
            raise SuricataCommandException(f"ruleset-reload-nonblocking command return with {cmd_out}")

    except Exception as e:
        return {"error": True, "error_value": f"Unable to refresh Suricata rule due to {e}"}

    return Response({"error": False})
