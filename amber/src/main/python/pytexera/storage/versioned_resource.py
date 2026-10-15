# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

import io
import os
import urllib.parse
import zipfile
from typing import List, Optional, Tuple

import requests

from .dataset_file_document import DatasetFileDocument
from .resource_type import ResourceType


class VersionedResource:
    """
    A dataset or model owned by the user running the workflow, read and written
    through file-service as that user (USER_JWT_TOKEN, the same identity a
    computing unit already carries).

    Writes are staged with `upload` and become visible only when `commit`
    creates a new version, so a reader always sees a whole version.
    """

    _TIMEOUT = (10, 300)

    def __init__(self, kind: ResourceType, name: str, create: bool = False):
        self.kind = kind
        self.name = name
        token = os.getenv("USER_JWT_TOKEN")
        if not token:
            raise ValueError("USER_JWT_TOKEN is not set; the run has no user identity.")
        self._headers = {"Authorization": f"Bearer {token}"}
        self._base = f"{self._file_service_api()}/{kind.value}"
        self.owner_email = ""
        self.id = self._find_id()
        if self.id is None:
            if not create:
                raise ValueError(f"No {kind.value} named '{name}' is owned by or shared with this user.")
            self.id = self._create()

    @staticmethod
    def _file_service_api() -> str:
        # The presign endpoint is the one file-service URL every deployment sets.
        presign = os.getenv(
            "FILE_SERVICE_GET_DATASET_PRESIGNED_URL_ENDPOINT",
            "http://localhost:9092/api/dataset/presign-download",
        )
        return presign.rsplit("/dataset/", 1)[0]

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        response = requests.request(
            method,
            f"{self._base}{path}",
            headers={**self._headers, **kwargs.pop("headers", {})},
            timeout=self._TIMEOUT,
            **kwargs,
        )
        if response.status_code >= 400:
            raise RuntimeError(
                f"{method} {self.kind.value}{path} failed "
                f"({response.status_code}): {response.text[:300]}"
            )
        return response

    def _find_id(self) -> Optional[int]:
        key, id_key = (
            ("dataset", "did") if self.kind == ResourceType.DATASET else ("model", "mid")
        )
        # One's own resource first; otherwise one another user shared, so pipelines
        # built by different people can read the same labels.
        named = [e for e in self._request("GET", "/list").json() if e[key]["name"] == self.name]
        for entry in sorted(named, key=lambda e: not e["isOwner"]):
            self.owner_email = entry["ownerEmail"]
            return entry[key][id_key]
        return None

    def _create(self) -> int:
        if self.kind == ResourceType.DATASET:
            body = {
                "datasetName": self.name,
                "datasetDescription": "",
                "isDatasetPublic": False,
                "isDatasetDownloadable": True,
            }
        else:
            body = {
                "modelName": self.name,
                "modelDescription": "",
                "isModelPublic": False,
                "isModelDownloadable": True,
                "framework": "pytorch",
                "format": "state-dict",
            }
        self._request("POST", "/create", json=body)
        created = self._find_id()
        if created is None:
            raise RuntimeError(f"Created {self.kind.value} '{self.name}' but cannot find it.")
        return created

    def latest_version(self) -> Optional[dict]:
        """The newest version's row (id, name, creation time), or None before the first."""
        latest = self._latest()
        return None if latest is None else latest[0]

    def versions(self) -> List[dict]:
        """Every version's row, oldest first."""
        rows = self._request("GET", f"/{self.id}/version/list").json()
        return sorted(rows, key=lambda row: row["dvid" if self.kind == ResourceType.DATASET else "mvid"])

    def latest_file_paths(self) -> List[str]:
        """Every file path in the newest version, relative to the version root."""
        latest = self._latest()
        return [] if latest is None else latest[1]

    def read_file(self, version_name: str, file_path: str) -> bytes:
        logical = f"/{self.kind.value}/{self.owner_email}/{self.name}/{version_name}/{file_path}"
        return DatasetFileDocument(logical).read_file().getvalue()

    def _latest(self) -> Optional[Tuple[dict, List[str]]]:
        response = requests.get(
            f"{self._base}/{self.id}/version/latest",
            headers=self._headers,
            timeout=self._TIMEOUT,
        )
        if response.status_code == 404:
            return None
        if response.status_code >= 400:
            raise RuntimeError(f"latest version failed ({response.status_code})")
        body = response.json()
        version = body["datasetVersion" if self.kind == ResourceType.DATASET else "modelVersion"]
        paths: List[str] = []

        def walk(nodes, prefix):
            for node in nodes or []:
                path = f"{prefix}{node['name']}"
                if node.get("type") == "directory":
                    walk(node.get("children"), f"{path}/")
                else:
                    paths.append(path)

        walk(body.get("fileNodes"), "")
        return version, paths

    def download_latest(self, dest_dir: str) -> Optional[dict]:
        """Extracts the newest version into dest_dir; returns that version's row."""
        version = self.latest_version()
        if version is None:
            return None
        zipped = self._request("GET", f"/{self.id}/versionZip", params={"latest": "true"})
        with zipfile.ZipFile(io.BytesIO(zipped.content)) as archive:
            archive.extractall(dest_dir)
        return version

    def upload(self, file_path: str, data: bytes) -> None:
        """Stages one file; it becomes part of the next version `commit` creates."""
        self._request(
            "POST",
            f"/{self.id}/upload",
            params={"filePath": urllib.parse.quote(file_path)},
            data=data,
            headers={"Content-Type": "application/octet-stream"},
        )

    def commit(self, version_name: str = "") -> dict:
        """Turns everything staged into a new version and returns its row."""
        response = self._request(
            "POST",
            f"/{self.id}/version/create",
            data=version_name.encode(),
            headers={"Content-Type": "text/plain"},
        )
        body = response.json()
        return body.get("datasetVersion", body.get("modelVersion", body))
