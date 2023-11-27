import json
import requests

headers = {"Authorization": "ya29.a0AfB_byDxkgdBeJn475hTGeGyufkGKsTZh_wEPo7dN2--Sgc4DKcF4pNL_kLlJE7f3V6_PyYqvKMhLFDdm7StvsnJuRbzV1KVgabRzO-j_9stEw1rwPnZOtDYgM8MR_92E8Ov2R8RN8bB8VRr2iFyQFByp6bCNNeZiMrWaCgYKAaMSARESFQHGX2MixLmYRR-h_lXEJoQ34Rg7dw0171"}
para = {
    "name": "##name for python uploaded file####",
}
files = {
    "data": ("metadata", json.dumps(para), "charset=UTF-8"),
    "file": open("decrypted_file.txt", "rb"),
}
r = requests.post(
        "https://www.googleapis.com/upload/drive/v3/files",
        headers=headers,
        files=files,
    )
print(r.text)