import os
import uuid

from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view
from rest_framework.response import Response

from lib.cuckoo.common.constants import CUCKOO_ROOT

YARA_BASE_FOLDER = os.path.join(CUCKOO_ROOT, "data", "yara")
YARA_CUSTOM_RULE_FOLDERS = [os.path.join(YARA_BASE_FOLDER, "custom"), os.path.join(YARA_BASE_FOLDER, "memory")]
SNORT_BASE_FOLDER = os.path.join("etc", "suricata", "rules")


@csrf_exempt
@api_view(["POST"])
def upload_yara(request):
    try:
        _id = request.data['id']
        body = request.data['body']
    except KeyError:
        return Response({'error': True, 'error_value': 'id or body not set in request'})

    filename = _id + '.yar'

    for folder in YARA_CUSTOM_RULE_FOLDERS:
        full_path = os.path.join(folder, filename)

        with open(full_path, 'w') as f:
            f.write(body)

    return Response({'yara': filename, 'error': False})


@csrf_exempt
@api_view(["DELETE"])
def delete_yara(request, _id):
    for folder in YARA_CUSTOM_RULE_FOLDERS:
        full_path = os.path.join(folder, f"{_id}.yar")
        try:
            os.remove(full_path)
        except FileNotFoundError:
            return Response({'error_value': 'Yara not found', 'error': True})

    return Response({'error': False})


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

    return Response({'error': False})


@csrf_exempt
@api_view(["POST"])
def upload_snort(request):
    try:
        _id = request.data['id']
        body = request.data['body']
    except KeyError:
        return Response({'error': True, 'error_value': 'id or body not set in request'})

    filename = _id + '.rules'
    full_path = os.path.join(SNORT_BASE_FOLDER, filename)

    with open(full_path, 'w') as f:
        f.write(body)

    return Response({'snort': filename, 'error': False})


@csrf_exempt
@api_view(["DELETE"])
def delete_snort(request, _id):
    full_path = os.path.join(SNORT_BASE_FOLDER, f"{_id}.rules")
    try:
        os.remove(full_path)
    except FileNotFoundError:
        return Response({'error_value': 'Snort not found', 'error': True})

    return Response({'error': False})


@csrf_exempt
@api_view(["POST"])
def clean_up_snort(request):
    for f in os.listdir(SNORT_BASE_FOLDER):
        try:
            uuid.UUID(f[:-4])
            os.remove(os.path.join(SNORT_BASE_FOLDER, f))
        except ValueError:
            # Rule is not a custom one
            pass

    return Response({'error': False})
