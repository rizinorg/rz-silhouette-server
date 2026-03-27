import json
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path

from ml_service.service import (
    App,
    ArtifactManifest,
    KeenHashIndex,
    RuntimePaths,
    build_server,
    build_runtime_paths,
    fit_centroids_from_dataset,
    initialize_artifacts,
    ingest_programs_from_dataset,
    normalize_bundle,
)


def demo_program(name: str, addr: int, digest: str) -> dict:
    return {
        "binary_type": "elf",
        "os": "linux",
        "arch": "x86",
        "bits": 64,
        "sections": [
            {"name": ".text", "size": 64, "paddr": 4096, "digest": "deadbeef"},
        ],
        "functions": [
            {
                "addr": addr,
                "size": 16,
                "bits": 64,
                "arch": "x86",
                "length": 16,
                "digest": digest,
                "section_name": ".text",
                "section_paddr": 4096,
                "loc": 4,
                "nos": 2,
                "pseudocode": f"int {name}(int x) {{ return x + 1; }}",
                "calls": [],
                "name": f"sym.{name}",
                "signature": f"int {name}(int)",
                "callconv": "sysv",
            }
        ],
    }


class KeenHashIndexTest(unittest.TestCase):
    def test_ingest_and_resolve(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = App(KeenHashIndex(Path(tmp)))
            shared = app.share({"program": demo_program("main", 0x1010, "cafe")})
            self.assertTrue(shared["binary_id"])
            resolved = app.resolve({"program": demo_program("main", 0x1010, "beef"), "topk": 3})
            self.assertEqual(shared["binary_id"], resolved["candidate_binary_ids"][0])
            self.assertEqual("sym.main", resolved["symbols"][0]["symbol"]["name"])

    def test_normalize_bundle_assigns_binary_id(self) -> None:
        bundle = normalize_bundle(demo_program("entry", 0x2020, "f00d"))
        self.assertTrue(bundle.binary_id)

    def test_ingest_and_fit_centroids_from_dataset(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifacts = root / "artifacts"
            paths = RuntimePaths(state_dir=root, artifacts_dir=artifacts)
            initialize_artifacts(paths, force=True, encoder_backend="hash", model_name_or_path="hash")

            dataset = root / "programs.jsonl"
            records = []
            for index_value in range(80):
                records.append(
                    json.dumps(
                        {
                            "program": demo_program(
                                f"fn{index_value}",
                                0x1000 + (index_value * 0x10),
                                f"{index_value:04x}",
                            )
                        }
                    )
                )
            dataset.write_text(
                "\n".join(records),
                encoding="utf-8",
            )

            index = KeenHashIndex(root, artifacts)
            ingest = ingest_programs_from_dataset(index, dataset)
            self.assertEqual(80, ingest["programs"])
            self.assertEqual(80, ingest["candidate_count"])

            result = fit_centroids_from_dataset(index, dataset, clusters=2, iterations=5)
            self.assertEqual(2, result["clusters"])
            self.assertTrue((artifacts / "centroids.npy").exists())
            self.assertTrue((artifacts / "centroid_labels.npy").exists())

    def test_initialize_artifacts_writes_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = build_runtime_paths(Path(tmp), None)
            payload = initialize_artifacts(paths, force=True, encoder_backend="hash", model_name_or_path="hash")
            self.assertEqual("hash", payload["encoder_backend"])
            manifest = ArtifactManifest.from_payload(json.loads(paths.manifest_path.read_text(encoding="utf-8")))
            self.assertEqual("hash", manifest.encoder_backend)


class ContractTest(unittest.TestCase):
    def test_http_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server = build_server("127.0.0.1:0", Path(tmp))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                time.sleep(0.1)
                host, port = server.server_address
                base = f"http://{host}:{port}"
                health = json.load(urllib.request.urlopen(f"{base}/healthz"))
                self.assertTrue(health["available"])

                body = json.dumps({"program": demo_program("start", 0x3030, "abba")}).encode("utf-8")
                req = urllib.request.Request(
                    f"{base}/v1/share",
                    data=body,
                    headers={"Content-Type": "application/json"},
                )
                share = json.load(urllib.request.urlopen(req))
                self.assertTrue(share["binary_id"])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
