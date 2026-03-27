from __future__ import annotations

import argparse
import os
import hashlib
import json
import logging
import math
import re
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Iterable, Sequence

import numpy as np

try:
    import faiss  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover
    faiss = None


DEFAULT_MODEL_NAME = "EleutherAI/pythia-410m-deduped"
DEFAULT_MODEL_VERSION = "keenhash-pythia410m-clip-v1"
DEFAULT_INDEX_VERSION = "keenhash-flat-v1"
DEFAULT_MAX_LENGTH = 2048
DEFAULT_EMBEDDING_DIM = 1024
DEFAULT_HASH_BITS = 65_536
DEFAULT_STRUCT_WEIGHT = 0.3
DEFAULT_SEMANTIC_WEIGHT = 0.7
DEFAULT_FUNCTION_THRESHOLD = 0.15
DEFAULT_POOLING = "last_token"
DEFAULT_BATCH_SIZE = 16
DEFAULT_TEMPERATURE = 0.05
DEFAULT_LEARNING_RATE = 2e-5
DEFAULT_WEIGHT_DECAY = 0.01
DEFAULT_WARMUP_RATIO = 0.05

TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|\d+")
SPACE_RE = re.compile(r"\s+")
NUMBER_RE = re.compile(r"\b\d+\b")
POPCOUNT = np.unpackbits(np.arange(256, dtype=np.uint8)[:, None], axis=1).sum(axis=1)


@dataclass
class SymbolRecord:
    name: str = ""
    signature: str = ""
    callconv: str = ""
    bits: int = 0


@dataclass
class FunctionRecord:
    addr: int = 0
    size: int = 0
    bits: int = 0
    arch: str = ""
    length: int = 0
    digest: str = ""
    section_name: str = ""
    section_paddr: int = 0
    loc: int = 0
    nos: int = 0
    pseudocode: str = ""
    pseudocode_source: str = "none"
    calls: list[int] = field(default_factory=list)
    name: str = ""
    signature: str = ""
    callconv: str = ""

    def symbol(self) -> SymbolRecord:
        return SymbolRecord(
            name=self.name,
            signature=self.signature,
            callconv=self.callconv,
            bits=self.bits,
        )


@dataclass
class SectionRecord:
    name: str = ""
    size: int = 0
    paddr: int = 0
    digest: str = ""


@dataclass
class ProgramBundle:
    binary_type: str = "any"
    os: str = "any"
    arch: str = "any"
    bits: int = 0
    binary_id: str = ""
    sections: list[SectionRecord] = field(default_factory=list)
    functions: list[FunctionRecord] = field(default_factory=list)
    topk: int = 0


@dataclass
class ArtifactManifest:
    schema_version: int = 1
    encoder_backend: str = "transformers"
    model_name_or_path: str = DEFAULT_MODEL_NAME
    model_version: str = DEFAULT_MODEL_VERSION
    index_version: str = DEFAULT_INDEX_VERSION
    embedding_dim: int = DEFAULT_EMBEDDING_DIM
    max_length: int = DEFAULT_MAX_LENGTH
    pooling: str = DEFAULT_POOLING
    normalize_embeddings: bool = True
    inference_batch_size: int = DEFAULT_BATCH_SIZE
    feature_hash_bits: int = DEFAULT_HASH_BITS
    centroid_topk: int = 1
    semantic_loc_alpha: float = 1.0
    semantic_nos_beta: float = 1.0
    semantic_weight_formula: str = "log1p_additive"
    struct_score_weight: float = DEFAULT_STRUCT_WEIGHT
    semantic_score_weight: float = DEFAULT_SEMANTIC_WEIGHT
    function_score_threshold: float = DEFAULT_FUNCTION_THRESHOLD
    semantic_index_factory: str = "Flat"
    semantic_metric: str = "ip"
    device: str = "auto"
    allow_fallback_hash_backend: bool = True
    contrastive_temperature: float = DEFAULT_TEMPERATURE
    learning_rate: float = DEFAULT_LEARNING_RATE
    weight_decay: float = DEFAULT_WEIGHT_DECAY
    warmup_ratio: float = DEFAULT_WARMUP_RATIO

    def __post_init__(self) -> None:
        self.embedding_dim = max(1, int(self.embedding_dim))
        self.max_length = max(1, int(self.max_length))
        self.inference_batch_size = max(1, int(self.inference_batch_size))
        self.feature_hash_bits = max(8, int(self.feature_hash_bits))
        if self.feature_hash_bits % 8:
            self.feature_hash_bits += 8 - (self.feature_hash_bits % 8)
        self.centroid_topk = max(1, int(self.centroid_topk))
        self.struct_score_weight = max(0.0, float(self.struct_score_weight))
        self.semantic_score_weight = max(0.0, float(self.semantic_score_weight))
        if self.struct_score_weight == 0.0 and self.semantic_score_weight == 0.0:
            self.struct_score_weight = DEFAULT_STRUCT_WEIGHT
            self.semantic_score_weight = DEFAULT_SEMANTIC_WEIGHT
        self.function_score_threshold = max(0.0, float(self.function_score_threshold))
        self.semantic_index_factory = self.semantic_index_factory.strip() or "Flat"
        metric = self.semantic_metric.strip().lower()
        self.semantic_metric = metric if metric in {"ip", "cosine", "l2"} else "ip"
        pooling = self.pooling.strip().lower()
        self.pooling = pooling if pooling in {"last_token", "mean"} else DEFAULT_POOLING
        self.contrastive_temperature = max(1e-6, float(self.contrastive_temperature))
        self.learning_rate = max(1e-8, float(self.learning_rate))
        self.weight_decay = max(0.0, float(self.weight_decay))
        self.warmup_ratio = min(1.0, max(0.0, float(self.warmup_ratio)))

    def to_payload(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "ArtifactManifest":
        return cls(**payload)


@dataclass(frozen=True)
class RuntimePaths:
    state_dir: Path
    artifacts_dir: Path

    @property
    def corpus_path(self) -> Path:
        return self.state_dir / "corpus.json"

    @property
    def manifest_path(self) -> Path:
        return self.artifacts_dir / "manifest.json"

    @property
    def centroids_path(self) -> Path:
        return self.artifacts_dir / "centroids.npy"

    @property
    def centroid_labels_path(self) -> Path:
        return self.artifacts_dir / "centroid_labels.npy"

    @property
    def semantic_index_path(self) -> Path:
        return self.state_dir / "semantic.index"


@dataclass
class IndexedFunction:
    addr: int = 0
    size: int = 0
    bits: int = 0
    arch: str = ""
    name: str = ""
    signature: str = ""
    callconv: str = ""
    pseudocode_source: str = "none"
    embedding: list[float] = field(default_factory=list)

    def symbol(self) -> SymbolRecord:
        return SymbolRecord(
            name=self.name,
            signature=self.signature,
            callconv=self.callconv,
            bits=self.bits,
        )


@dataclass
class ProgramIndexEntry:
    program: ProgramBundle
    sem_vector: list[float]
    struct_vector_hex: str
    functions: list[IndexedFunction]

    def to_payload(self) -> dict[str, Any]:
        return {
            "program": {
                "binary_type": self.program.binary_type,
                "os": self.program.os,
                "arch": self.program.arch,
                "bits": self.program.bits,
                "binary_id": self.program.binary_id,
                "sections": [asdict(section) for section in self.program.sections],
                "functions": [asdict(function) for function in self.program.functions],
                "topk": self.program.topk,
            },
            "sem_vector": self.sem_vector,
            "struct_vector_hex": self.struct_vector_hex,
            "functions": [asdict(function) for function in self.functions],
        }

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "ProgramIndexEntry":
        program = normalize_bundle(payload["program"])
        functions = [IndexedFunction(**function) for function in payload.get("functions", [])]
        return cls(
            program=program,
            sem_vector=[float(value) for value in payload.get("sem_vector", [])],
            struct_vector_hex=str(payload.get("struct_vector_hex", "")),
            functions=functions,
        )


@dataclass
class EncodedProgram:
    bundle: ProgramBundle
    sem_vector: np.ndarray
    struct_vector: np.ndarray
    functions: list[IndexedFunction]

    def to_entry(self) -> ProgramIndexEntry:
        return ProgramIndexEntry(
            program=self.bundle,
            sem_vector=self.sem_vector.astype(np.float32).tolist(),
            struct_vector_hex=self.struct_vector.tobytes().hex(),
            functions=self.functions,
        )


def normalize_text(value: str) -> str:
    value = value.strip().lower()
    value = NUMBER_RE.sub("<num>", value)
    return SPACE_RE.sub(" ", value)


def stable_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def stable_index(value: str, mod: int) -> int:
    return int.from_bytes(hashlib.sha256(value.encode("utf-8")).digest()[:8], "little") % max(1, mod)


def signed_hash(value: str) -> int:
    return 1 if stable_index(value, 2) == 0 else -1


def to_hex_bytes(raw: Any) -> str:
    if isinstance(raw, str):
        return raw
    if isinstance(raw, bytes):
        return raw.hex()
    return bytes(raw).hex()


def normalize_bundle(payload: dict[str, Any]) -> ProgramBundle:
    sections = [
        SectionRecord(
            name=str(section.get("name", "")).strip(),
            size=int(section.get("size", 0)),
            paddr=int(section.get("paddr", 0)),
            digest=to_hex_bytes(section.get("digest", "")),
        )
        for section in payload.get("sections", [])
    ]
    functions = [
        FunctionRecord(
            addr=int(function.get("addr", 0)),
            size=int(function.get("size", 0)),
            bits=int(function.get("bits", 0)),
            arch=str(function.get("arch", payload.get("arch", "any"))).strip().lower() or "any",
            length=int(function.get("length", function.get("size", 0))),
            digest=to_hex_bytes(function.get("digest", "")),
            section_name=str(function.get("section_name", function.get("sectionName", ""))).strip(),
            section_paddr=int(function.get("section_paddr", function.get("sectionPaddr", 0))),
            loc=int(function.get("loc", 0)),
            nos=int(function.get("nos", 0)),
            pseudocode=normalize_text(str(function.get("pseudocode", ""))),
            pseudocode_source=str(function.get("pseudocode_source", function.get("pseudocodeSource", "none"))).strip().lower() or "none",
            calls=[int(value) for value in function.get("calls", [])],
            name=str(function.get("name", "")).strip(),
            signature=str(function.get("signature", "")).strip(),
            callconv=str(function.get("callconv", "")).strip().lower(),
        )
        for function in payload.get("functions", [])
    ]
    bundle = ProgramBundle(
        binary_type=str(payload.get("binary_type", payload.get("binaryType", "any"))).strip().lower() or "any",
        os=str(payload.get("os", "any")).strip().lower() or "any",
        arch=str(payload.get("arch", "any")).strip().lower() or "any",
        bits=int(payload.get("bits", 0)),
        binary_id=str(payload.get("binary_id", payload.get("binaryId", ""))).strip(),
        sections=sections,
        functions=functions,
        topk=int(payload.get("topk", 0)),
    )
    if not bundle.binary_id:
        bundle.binary_id = compute_binary_id(bundle)
    return bundle


def compute_binary_id(bundle: ProgramBundle) -> str:
    payload = {
        "binary_type": bundle.binary_type,
        "os": bundle.os,
        "arch": bundle.arch,
        "bits": bundle.bits,
        "sections": [asdict(section) for section in bundle.sections],
        "functions": [asdict(function) for function in bundle.functions],
    }
    return stable_hex(json.dumps(payload, separators=(",", ":"), sort_keys=False))


def function_embedding_text(function: FunctionRecord, bundle: ProgramBundle) -> str:
    if function.pseudocode:
        return function.pseudocode
    fields = [
        f"arch {function.arch or bundle.arch}",
        f"bits {function.bits or bundle.bits}",
        f"section {function.section_name}",
        f"digest {function.digest}",
    ]
    return normalize_text(" ".join(field for field in fields if field.strip()))


def pseudocode_source_weight(source: str) -> float:
    source = (source or "none").strip().lower()
    if source == "ghidra":
        return 1.0
    if source == "pseudo":
        return 0.7
    return 0.45


def l2_normalize_rows(matrix: np.ndarray) -> np.ndarray:
    if matrix.size == 0:
        return matrix.astype(np.float32, copy=False)
    matrix = np.asarray(matrix, dtype=np.float32)
    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    norms[norms == 0.0] = 1.0
    return matrix / norms


def l2_normalize_vector(vector: np.ndarray) -> np.ndarray:
    vector = np.asarray(vector, dtype=np.float32)
    if vector.size == 0:
        return vector
    norm = float(np.linalg.norm(vector))
    if norm == 0.0:
        return vector
    return vector / norm


def pool_hidden_states(hidden: Any, attention_mask: Any, pooling: str, torch_module: Any) -> Any:
    if pooling == "mean":
        mask = attention_mask.unsqueeze(-1)
        masked = hidden * mask
        return masked.sum(dim=1) / mask.sum(dim=1).clamp(min=1)
    last_indices = attention_mask.sum(dim=1).clamp(min=1) - 1
    return hidden[torch_module.arange(hidden.size(0), device=hidden.device), last_indices]


def feature_hash_labels(labels: Iterable[int], hash_bits: int) -> np.ndarray:
    accum = np.zeros(hash_bits, dtype=np.int16)
    for label in labels:
        bucket = stable_index(f"bucket:{label}", hash_bits)
        accum[bucket] += signed_hash(f"sign:{label}")
    return np.packbits((accum != 0).astype(np.uint8))


def semantic_function_weight(function: FunctionRecord, manifest: ArtifactManifest) -> float:
    if manifest.semantic_weight_formula == "linear":
        return 1.0 + manifest.semantic_loc_alpha * max(0, function.loc) + manifest.semantic_nos_beta * max(0, function.nos)
    loc_factor = math.log1p(max(0, function.loc))
    nos_factor = math.log1p(max(0, function.nos))
    return 1.0 + manifest.semantic_loc_alpha * loc_factor + manifest.semantic_nos_beta * nos_factor


def semantic_program_vector(
    functions: Sequence[FunctionRecord],
    embeddings: np.ndarray,
    manifest: ArtifactManifest,
) -> np.ndarray:
    if embeddings.size == 0:
        return np.zeros((manifest.embedding_dim,), dtype=np.float32)
    total = 0.0
    vector = np.zeros((embeddings.shape[1],), dtype=np.float32)
    for function, embedding in zip(functions, embeddings, strict=False):
        weight = semantic_function_weight(function, manifest) * pseudocode_source_weight(function.pseudocode_source)
        total += weight
        vector += embedding * weight
    if total > 0.0:
        vector /= total
    return l2_normalize_vector(vector).astype(np.float32, copy=False)


def structural_program_vector(
    functions: Sequence[FunctionRecord],
    embeddings: np.ndarray,
    manifest: ArtifactManifest,
    classifier: "CentroidClassifier | None",
) -> np.ndarray:
    label_bag: list[int] = []
    if classifier is not None:
        for labels in classifier.classify(embeddings, manifest.centroid_topk):
            label_bag.extend(labels)
    else:
        label_space = max(manifest.feature_hash_bits * 4, 1024)
        for function, embedding in zip(functions, embeddings, strict=False):
            seed = function.digest or function.pseudocode or str(function.addr)
            label_bag.append(stable_index(f"label:{seed}:{embedding[:8].tobytes().hex()}", label_space))
    return feature_hash_labels(label_bag, manifest.feature_hash_bits)


def structural_jaccard_scores(query: np.ndarray, matrix: np.ndarray) -> np.ndarray:
    if matrix.size == 0:
        return np.zeros((0,), dtype=np.float32)
    query = np.asarray(query, dtype=np.uint8).reshape(1, -1)
    intersections = POPCOUNT[np.bitwise_and(matrix, query)].sum(axis=1)
    unions = POPCOUNT[np.bitwise_or(matrix, query)].sum(axis=1)
    scores = np.zeros(matrix.shape[0], dtype=np.float32)
    valid = unions > 0
    scores[valid] = intersections[valid] / unions[valid]
    return scores


def top_indices(values: np.ndarray, limit: int) -> np.ndarray:
    if values.size == 0 or limit <= 0:
        return np.zeros((0,), dtype=np.int32)
    limit = min(limit, values.shape[0])
    if limit >= values.shape[0]:
        return np.argsort(-values)
    indices = np.argpartition(-values, limit - 1)[:limit]
    return indices[np.argsort(-values[indices])]


def faiss_metric(manifest: ArtifactManifest) -> int:
    if manifest.semantic_metric == "l2":
        return faiss.METRIC_L2
    return faiss.METRIC_INNER_PRODUCT


def build_faiss_index(matrix: np.ndarray, manifest: ArtifactManifest) -> Any:
    if faiss is None or matrix.size == 0:
        return None
    metric = faiss_metric(manifest)
    factory = manifest.semantic_index_factory.strip()
    if factory.lower() == "flat":
        if metric == faiss.METRIC_L2:
            index = faiss.IndexFlatL2(matrix.shape[1])
        else:
            index = faiss.IndexFlatIP(matrix.shape[1])
    else:
        index = faiss.index_factory(matrix.shape[1], factory, metric)
        if not index.is_trained:
            index.train(matrix)
    index.add(matrix)
    return index


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile("w", delete=False, dir=path.parent, encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.flush()
        temp_path = Path(handle.name)
    temp_path.replace(path)


def atomic_numpy_save(path: Path, payload: np.ndarray) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile("wb", delete=False, dir=path.parent) as handle:
        np.save(handle, payload)
        temp_path = Path(handle.name)
    temp_path.replace(path)


class BaseFunctionEncoder:
    backend = "base"

    def __init__(self, manifest: ArtifactManifest) -> None:
        self.manifest = manifest
        self.dimension = manifest.embedding_dim
        self.model_version = manifest.model_version
        self.fallback = False

    def encode(self, texts: Sequence[str]) -> np.ndarray:
        raise NotImplementedError


class HashFunctionEncoder(BaseFunctionEncoder):
    backend = "hash"

    def __init__(self, manifest: ArtifactManifest) -> None:
        super().__init__(manifest)
        self.model_version = f"{manifest.model_version}+hash-fallback"
        self.fallback = True

    def encode(self, texts: Sequence[str]) -> np.ndarray:
        if not texts:
            return np.zeros((0, self.dimension), dtype=np.float32)
        matrix = np.zeros((len(texts), self.dimension), dtype=np.float32)
        for row, text in enumerate(texts):
            tokens = TOKEN_RE.findall(normalize_text(text))
            if not tokens:
                tokens = ["<empty>"]
            for token in tokens:
                index = stable_index(f"tok:{token}", self.dimension)
                matrix[row, index] += signed_hash(f"sgn:{token}")
        return l2_normalize_rows(matrix)


class TransformerFunctionEncoder(BaseFunctionEncoder):
    backend = "transformers"

    def __init__(self, manifest: ArtifactManifest) -> None:
        super().__init__(manifest)
        import torch
        from transformers import AutoModel, AutoTokenizer

        self._torch = torch
        device = manifest.device.strip().lower()
        if device in ("", "auto"):
            device = "cuda" if torch.cuda.is_available() else "cpu"
        self.device = torch.device(device)
        self.tokenizer = AutoTokenizer.from_pretrained(manifest.model_name_or_path, trust_remote_code=False)
        if self.tokenizer.pad_token is None:
            if self.tokenizer.eos_token is not None:
                self.tokenizer.pad_token = self.tokenizer.eos_token
            elif self.tokenizer.unk_token is not None:
                self.tokenizer.pad_token = self.tokenizer.unk_token
        self.model = AutoModel.from_pretrained(manifest.model_name_or_path, trust_remote_code=False)
        self.model.eval()
        self.model.to(self.device)
        self.dimension = int(getattr(self.model.config, "hidden_size", manifest.embedding_dim))

    def encode(self, texts: Sequence[str]) -> np.ndarray:
        if not texts:
            return np.zeros((0, self.dimension), dtype=np.float32)
        torch = self._torch
        vectors: list[np.ndarray] = []
        batch_size = min(len(texts), self.manifest.inference_batch_size)
        for offset in range(0, len(texts), batch_size):
            batch = [text or "<empty>" for text in texts[offset : offset + batch_size]]
            encoded = self.tokenizer(
                batch,
                return_tensors="pt",
                padding=True,
                truncation=True,
                max_length=self.manifest.max_length,
            )
            encoded = {key: value.to(self.device) for key, value in encoded.items()}
            with torch.inference_mode():
                outputs = self.model(**encoded)
                hidden = outputs.last_hidden_state
                pooled = pool_hidden_states(hidden, encoded["attention_mask"], self.manifest.pooling, torch)
            vectors.append(pooled.float().cpu().numpy())
        matrix = np.concatenate(vectors, axis=0).astype(np.float32, copy=False)
        if self.manifest.normalize_embeddings:
            matrix = l2_normalize_rows(matrix)
        return matrix


class CentroidClassifier:
    def __init__(self, centroids: np.ndarray, labels: np.ndarray | None = None) -> None:
        centroids = np.asarray(centroids, dtype=np.float32)
        if centroids.ndim != 2:
            raise ValueError("centroids must be a 2D matrix")
        self.centroids = l2_normalize_rows(centroids)
        if labels is None:
            labels = np.arange(self.centroids.shape[0], dtype=np.int32)
        self.labels = np.asarray(labels, dtype=np.int32)
        self.index = None
        if faiss is not None and self.centroids.size:
            index = faiss.IndexFlatIP(self.centroids.shape[1])
            index.add(self.centroids)
            self.index = index

    @classmethod
    def load(cls, paths: RuntimePaths) -> "CentroidClassifier | None":
        if not paths.centroids_path.exists():
            return None
        centroids = np.load(paths.centroids_path)
        labels = np.load(paths.centroid_labels_path) if paths.centroid_labels_path.exists() else None
        return cls(centroids, labels)

    @classmethod
    def fit(
        cls,
        embeddings: np.ndarray,
        clusters: int,
        iterations: int = 30,
        seed: int = 0,
        use_gpu: bool = False,
    ) -> "CentroidClassifier":
        embeddings = l2_normalize_rows(np.asarray(embeddings, dtype=np.float32))
        if embeddings.ndim != 2 or embeddings.size == 0:
            raise ValueError("embeddings must be a non-empty matrix")
        if faiss is not None:
            kmeans = faiss.Kmeans(
                embeddings.shape[1],
                clusters,
                niter=iterations,
                seed=seed,
                gpu=use_gpu,
                spherical=True,
                verbose=False,
            )
            kmeans.train(embeddings)
            centroids = np.asarray(kmeans.centroids, dtype=np.float32).reshape(clusters, embeddings.shape[1])
            return cls(centroids)
        from sklearn.cluster import MiniBatchKMeans

        model = MiniBatchKMeans(
            n_clusters=clusters,
            max_iter=iterations,
            random_state=seed,
            batch_size=min(4096, max(256, embeddings.shape[0] // 8 or 256)),
            n_init="auto",
        )
        model.fit(embeddings)
        return cls(np.asarray(model.cluster_centers_, dtype=np.float32))

    def save(self, paths: RuntimePaths) -> None:
        atomic_numpy_save(paths.centroids_path, self.centroids)
        atomic_numpy_save(paths.centroid_labels_path, self.labels)

    def classify(self, embeddings: np.ndarray, topk: int) -> list[list[int]]:
        embeddings = l2_normalize_rows(np.asarray(embeddings, dtype=np.float32))
        if embeddings.size == 0 or self.centroids.size == 0:
            return [[] for _ in range(len(embeddings))]
        topk = min(max(1, int(topk)), self.centroids.shape[0])
        if self.index is not None:
            _, indices = self.index.search(embeddings, topk)
        else:
            scores = embeddings @ self.centroids.T
            if topk >= scores.shape[1]:
                indices = np.argsort(-scores, axis=1)
            else:
                partition = np.argpartition(-scores, topk - 1, axis=1)[:, :topk]
                order = np.take_along_axis(scores, partition, axis=1).argsort(axis=1)[:, ::-1]
                indices = np.take_along_axis(partition, order, axis=1)
        return [[int(self.labels[index]) for index in row if index >= 0] for row in indices]


class ArtifactRuntime:
    def __init__(self, paths: RuntimePaths, logger: logging.Logger | None = None) -> None:
        self.paths = paths
        self.logger = logger or logging.getLogger("ml_service")
        self.paths.state_dir.mkdir(parents=True, exist_ok=True)
        self.paths.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.manifest = ArtifactManifest()
        self.fallback_reason = ""
        self.encoder: BaseFunctionEncoder = HashFunctionEncoder(self.manifest)
        self.classifier: CentroidClassifier | None = None
        self.reload()

    def _load_manifest(self) -> ArtifactManifest:
        if self.paths.manifest_path.exists():
            payload = json.loads(self.paths.manifest_path.read_text(encoding="utf-8"))
            return ArtifactManifest.from_payload(payload)
        manifest = ArtifactManifest()
        self.save_manifest(manifest)
        return manifest

    def save_manifest(self, manifest: ArtifactManifest | None = None) -> None:
        if manifest is not None:
            self.manifest = manifest
        atomic_write_json(self.paths.manifest_path, self.manifest.to_payload())

    def reload(self) -> None:
        self.manifest = self._load_manifest()
        self.fallback_reason = ""
        self.encoder = self._load_encoder()
        if self.manifest.embedding_dim != self.encoder.dimension:
            self.manifest.embedding_dim = self.encoder.dimension
            self.save_manifest()
        self.classifier = CentroidClassifier.load(self.paths)

    def _load_encoder(self) -> BaseFunctionEncoder:
        if self.manifest.encoder_backend == "hash":
            return HashFunctionEncoder(self.manifest)
        model_path = Path(self.manifest.model_name_or_path)
        allow_remote = os.environ.get("RZ_SILHOUETTE_ALLOW_REMOTE_MODEL", "").strip() == "1"
        if not model_path.exists() and not allow_remote:
            self.fallback_reason = (
                "transformer model artifacts are not configured locally; "
                "set manifest.model_name_or_path to a local checkpoint or "
                "export RZ_SILHOUETTE_ALLOW_REMOTE_MODEL=1"
            )
            self.logger.warning("falling back to hash encoder: %s", self.fallback_reason)
            return HashFunctionEncoder(self.manifest)
        try:
            return TransformerFunctionEncoder(self.manifest)
        except Exception as exc:  # pragma: no cover
            if not self.manifest.allow_fallback_hash_backend:
                raise
            self.fallback_reason = str(exc)
            self.logger.warning("falling back to hash encoder: %s", exc)
            return HashFunctionEncoder(self.manifest)

    @property
    def model_version(self) -> str:
        return self.encoder.model_version

    @property
    def index_version(self) -> str:
        return self.manifest.index_version

    def encode_program(self, bundle: ProgramBundle) -> EncodedProgram:
        texts = [function_embedding_text(function, bundle) for function in bundle.functions]
        embeddings = self.encoder.encode(texts)
        sem_vector = semantic_program_vector(bundle.functions, embeddings, self.manifest)
        struct_vector = structural_program_vector(bundle.functions, embeddings, self.manifest, self.classifier)
        functions = []
        for function, embedding in zip(bundle.functions, embeddings, strict=False):
            functions.append(
                IndexedFunction(
                    addr=function.addr,
                    size=function.size,
                    bits=function.bits or bundle.bits,
                    arch=function.arch or bundle.arch,
                    name=function.name,
                    signature=function.signature,
                    callconv=function.callconv,
                    pseudocode_source=function.pseudocode_source,
                    embedding=embedding.astype(np.float32).tolist(),
                )
            )
        return EncodedProgram(bundle=bundle, sem_vector=sem_vector, struct_vector=struct_vector, functions=functions)

    def health(self, corpus_size: int) -> dict[str, Any]:
        model_path = Path(self.manifest.model_name_or_path)
        return {
            "available": True,
            "model_version": self.model_version,
            "index_version": self.index_version,
            "encoder_backend": self.encoder.backend,
            "fallback_active": self.encoder.fallback,
            "fallback_reason": self.fallback_reason,
            "faiss_available": faiss is not None,
            "centroids_loaded": self.classifier is not None,
            "feature_hash_bits": self.manifest.feature_hash_bits,
            "embedding_dim": self.encoder.dimension,
            "corpus_size": corpus_size,
            "state_dir": str(self.paths.state_dir),
            "artifacts_dir": str(self.paths.artifacts_dir),
            "semantic_index_factory": self.manifest.semantic_index_factory,
            "semantic_metric": self.manifest.semantic_metric,
            "manifest_path": str(self.paths.manifest_path),
            "semantic_index_path": str(self.paths.semantic_index_path),
            "model_artifacts_local": model_path.exists(),
        }


class KeenHashIndex:
    def __init__(self, state_dir: Path | None = None, artifacts_dir: Path | None = None) -> None:
        state_root = Path(state_dir) if state_dir is not None else Path.cwd() / "state"
        artifact_root = Path(artifacts_dir) if artifacts_dir is not None else state_root / "artifacts"
        self.logger = logging.getLogger("ml_service")
        self.lock = threading.RLock()
        self.paths = RuntimePaths(state_dir=state_root, artifacts_dir=artifact_root)
        self.runtime = ArtifactRuntime(self.paths, logger=self.logger)
        self.entries: dict[str, ProgramIndexEntry] = {}
        self.binary_ids: list[str] = []
        self.semantic_matrix = np.zeros((0, self.runtime.encoder.dimension), dtype=np.float32)
        self.struct_matrix = np.zeros((0, self.runtime.manifest.feature_hash_bits // 8), dtype=np.uint8)
        self.semantic_index = None
        self._load()

    def _load(self) -> None:
        if not self.paths.corpus_path.exists():
            return
        payload = json.loads(self.paths.corpus_path.read_text(encoding="utf-8"))
        for raw in payload.get("entries", []):
            entry = ProgramIndexEntry.from_payload(raw)
            self.entries[entry.program.binary_id] = entry
        self._rebuild_indexes_locked()
        self._load_persisted_semantic_index_locked()

    def _load_persisted_semantic_index_locked(self) -> None:
        if faiss is None or not self.paths.semantic_index_path.exists() or not self.binary_ids:
            return
        try:
            index = faiss.read_index(str(self.paths.semantic_index_path))
        except Exception as exc:  # pragma: no cover
            self.logger.warning("failed to read semantic index %s: %s", self.paths.semantic_index_path, exc)
            return
        expected_dim = self.semantic_matrix.shape[1] if self.semantic_matrix.ndim == 2 else 0
        if index.d != expected_dim or index.ntotal != len(self.binary_ids):
            self.logger.warning(
                "semantic index shape mismatch; rebuilding in-memory index (d=%s/%s, ntotal=%s/%s)",
                index.d,
                expected_dim,
                index.ntotal,
                len(self.binary_ids),
            )
            return
        self.semantic_index = index

    def _persist_locked(self) -> None:
        payload = {"entries": [entry.to_payload() for entry in self.entries.values()]}
        atomic_write_json(self.paths.corpus_path, payload)
        if faiss is not None and self.semantic_index is not None:
            faiss.write_index(self.semantic_index, str(self.paths.semantic_index_path))

    def _rebuild_indexes_locked(self) -> None:
        ordered = [self.entries[key] for key in sorted(self.entries)]
        self.binary_ids = [entry.program.binary_id for entry in ordered]
        if not ordered:
            self.semantic_matrix = np.zeros((0, self.runtime.encoder.dimension), dtype=np.float32)
            self.struct_matrix = np.zeros((0, self.runtime.manifest.feature_hash_bits // 8), dtype=np.uint8)
            self.semantic_index = None
            return

        self.semantic_matrix = l2_normalize_rows(
            np.asarray([entry.sem_vector for entry in ordered], dtype=np.float32)
        )
        self.struct_matrix = np.asarray(
            [np.frombuffer(bytes.fromhex(entry.struct_vector_hex), dtype=np.uint8) for entry in ordered],
            dtype=np.uint8,
        )
        self.semantic_index = None
        if self.semantic_matrix.size:
            self.semantic_index = build_faiss_index(self.semantic_matrix, self.runtime.manifest)

    def ingest(self, bundle: ProgramBundle) -> dict[str, Any]:
        bundle = normalize_bundle(asdict(bundle))
        encoded = self.runtime.encode_program(bundle)
        with self.lock:
            self.entries[bundle.binary_id] = encoded.to_entry()
            self._rebuild_indexes_locked()
            self._persist_locked()
            return {
                "binary_id": bundle.binary_id,
                "candidate_count": len(self.entries),
                "model_version": self.runtime.model_version,
                "index_version": self.runtime.index_version,
            }

    def reindex_all(self) -> dict[str, Any]:
        with self.lock:
            ordered = [normalize_bundle(asdict(entry.program)) for entry in self.entries.values()]
            rebuilt: dict[str, ProgramIndexEntry] = {}
            for bundle in ordered:
                rebuilt[bundle.binary_id] = self.runtime.encode_program(bundle).to_entry()
            self.entries = rebuilt
            self._rebuild_indexes_locked()
            self._persist_locked()
            return {
                "candidate_count": len(self.entries),
                "model_version": self.runtime.model_version,
                "index_version": self.runtime.index_version,
            }

    def resolve(self, bundle: ProgramBundle, topk: int) -> dict[str, Any]:
        bundle = normalize_bundle(asdict(bundle))
        encoded = self.runtime.encode_program(bundle)
        topk = max(1, int(topk or bundle.topk or 10))
        with self.lock:
            if not self.binary_ids:
                return {
                    "candidate_binary_ids": [],
                    "symbols": [],
                    "model_version": self.runtime.model_version,
                    "index_version": self.runtime.index_version,
                }

            struct_scores = structural_jaccard_scores(encoded.struct_vector, self.struct_matrix)
            pool_limit = min(len(self.binary_ids), max(topk * 8, 64))
            semantic_scores = self._semantic_candidate_scores_locked(encoded.sem_vector, pool_limit)
            structural_pool = top_indices(struct_scores, pool_limit)

            candidate_indices = set(structural_pool.tolist())
            candidate_indices.update(semantic_scores.keys())
            if not candidate_indices:
                candidate_indices = set(range(len(self.binary_ids)))

            ranking: list[tuple[float, int]] = []
            for index in candidate_indices:
                score = (
                    self.runtime.manifest.semantic_score_weight * semantic_scores.get(index, 0.0)
                    + self.runtime.manifest.struct_score_weight * float(struct_scores[index])
                )
                if score > 0.0:
                    ranking.append((score, index))
            ranking.sort(key=lambda item: item[0], reverse=True)
            ranking = ranking[:topk]
            candidate_binary_ids = [self.binary_ids[index] for _, index in ranking]
            symbols = self._approximate_symbols_locked(encoded.functions, candidate_binary_ids)
            return {
                "candidate_binary_ids": candidate_binary_ids,
                "symbols": symbols,
                "model_version": self.runtime.model_version,
                "index_version": self.runtime.index_version,
            }

    def _semantic_candidate_scores_locked(self, vector: np.ndarray, limit: int) -> dict[int, float]:
        if self.semantic_matrix.size == 0:
            return {}
        vector = l2_normalize_vector(np.asarray(vector, dtype=np.float32))
        limit = min(limit, len(self.binary_ids))
        use_l2 = self.runtime.manifest.semantic_metric == "l2"
        if self.semantic_index is not None:
            scores, indices = self.semantic_index.search(vector.reshape(1, -1), limit)
            out: dict[int, float] = {}
            for score, index in zip(scores[0], indices[0], strict=False):
                if index < 0:
                    continue
                value = 1.0 / (1.0 + float(score)) if use_l2 else float(score)
                if value > 0.0:
                    out[int(index)] = value
            return out
        if use_l2:
            distances = np.linalg.norm(self.semantic_matrix - vector.reshape(1, -1), axis=1)
            indices = np.argsort(distances)[:limit]
            return {int(index): float(1.0 / (1.0 + distances[index])) for index in indices}
        dot = self.semantic_matrix @ vector
        indices = top_indices(dot, limit)
        return {int(index): float(dot[index]) for index in indices if dot[index] > 0.0}

    def _approximate_symbols_locked(
        self,
        query_functions: Sequence[IndexedFunction],
        candidate_binary_ids: Sequence[str],
    ) -> list[dict[str, Any]]:
        threshold = self.runtime.manifest.function_score_threshold
        candidates: list[tuple[str, IndexedFunction, np.ndarray]] = []
        for binary_id in candidate_binary_ids:
            entry = self.entries.get(binary_id)
            if entry is None:
                continue
            for function in entry.functions:
                if not function.name:
                    continue
                candidates.append(
                    (
                        binary_id,
                        function,
                        l2_normalize_vector(np.asarray(function.embedding, dtype=np.float32)),
                    )
                )

        results: list[dict[str, Any]] = []
        for query in query_functions:
            query_vector = l2_normalize_vector(np.asarray(query.embedding, dtype=np.float32))
            if not np.any(query_vector):
                continue
            best_score = 0.0
            best_binary_id = ""
            best_function: IndexedFunction | None = None
            for binary_id, function, candidate_vector in candidates:
                if query.bits and function.bits and query.bits != function.bits:
                    continue
                if query.arch and function.arch and query.arch != function.arch:
                    continue
                score = float(np.dot(query_vector, candidate_vector))
                score *= min(
                    pseudocode_source_weight(query.pseudocode_source),
                    pseudocode_source_weight(function.pseudocode_source),
                )
                if score > best_score:
                    best_score = score
                    best_binary_id = binary_id
                    best_function = function
            if best_function is None or best_score < threshold:
                continue
            results.append(
                {
                    "addr": query.addr,
                    "symbol": asdict(best_function.symbol()),
                    "confidence": round(best_score, 4),
                    "exact": False,
                    "matched_binary_id": best_binary_id,
                    "matched_by": "keenhash_sem",
                }
            )
        return results


def iter_json_records(path: Path) -> Iterable[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(path)
    if path.suffix.lower() == ".jsonl":
        with path.open("r", encoding="utf-8") as handle:
            for lineno, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                payload = json.loads(line)
                if not isinstance(payload, dict):
                    raise ValueError(f"{path}:{lineno}: expected JSON object")
                yield payload
        return
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        for key in ("records", "entries", "programs", "pairs", "items"):
            values = payload.get(key)
            if isinstance(values, list):
                payload = values
                break
        else:
            payload = [payload]
    if not isinstance(payload, list):
        raise ValueError(f"{path}: expected list-like JSON payload")
    for index, record in enumerate(payload, start=1):
        if not isinstance(record, dict):
            raise ValueError(f"{path}:{index}: expected JSON object")
        yield record


def first_text(record: dict[str, Any], keys: Sequence[str]) -> str:
    for key in keys:
        value = record.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def load_function_pairs(path: Path, limit: int = 0) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for record in iter_json_records(path):
        left = first_text(record, ("source", "source_text", "anchor", "query", "text_a"))
        right = first_text(record, ("pseudocode", "pseudo", "target", "positive", "text_b"))
        if not left or not right:
            continue
        pairs.append((normalize_text(left), normalize_text(right)))
        if limit > 0 and len(pairs) >= limit:
            break
    return pairs


def load_program_bundles(path: Path, limit: int = 0) -> list[ProgramBundle]:
    bundles: list[ProgramBundle] = []
    for record in iter_json_records(path):
        program = record.get("program", record)
        if not isinstance(program, dict):
            continue
        bundles.append(normalize_bundle(program))
        if limit > 0 and len(bundles) >= limit:
            break
    return bundles


def build_runtime_paths(state_dir: Path | None, artifacts_dir: Path | None) -> RuntimePaths:
    state_root = Path(state_dir) if state_dir is not None else Path.cwd() / "state"
    artifact_root = Path(artifacts_dir) if artifacts_dir is not None else state_root / "artifacts"
    return RuntimePaths(state_dir=state_root, artifacts_dir=artifact_root)


def initialize_artifacts(
    paths: RuntimePaths,
    *,
    force: bool = False,
    encoder_backend: str = "transformers",
    model_name_or_path: str = DEFAULT_MODEL_NAME,
) -> dict[str, Any]:
    if paths.manifest_path.exists() and not force:
        manifest = ArtifactManifest.from_payload(json.loads(paths.manifest_path.read_text(encoding="utf-8")))
    else:
        manifest = ArtifactManifest(encoder_backend=encoder_backend, model_name_or_path=model_name_or_path)
        atomic_write_json(paths.manifest_path, manifest.to_payload())
    return {
        "manifest_path": str(paths.manifest_path),
        "artifacts_dir": str(paths.artifacts_dir),
        "model_name_or_path": manifest.model_name_or_path,
        "encoder_backend": manifest.encoder_backend,
    }


def encode_training_batch(model: Any, encoded: dict[str, Any], manifest: ArtifactManifest, torch_module: Any) -> Any:
    outputs = model(**encoded)
    pooled = pool_hidden_states(outputs.last_hidden_state, encoded["attention_mask"], manifest.pooling, torch_module)
    if manifest.normalize_embeddings:
        pooled = torch_module.nn.functional.normalize(pooled.float(), p=2, dim=1)
    return pooled


def train_encoder(
    paths: RuntimePaths,
    dataset_path: Path,
    *,
    output_dir: Path | None = None,
    epochs: int = 1,
    limit_pairs: int = 0,
    seed: int = 0,
    log_every: int = 10,
) -> dict[str, Any]:
    pairs = load_function_pairs(dataset_path, limit_pairs)
    if len(pairs) < 2:
        raise ValueError("training requires at least two source/pseudocode pairs")

    import random

    import torch
    from transformers import AutoModel, AutoTokenizer, get_linear_schedule_with_warmup

    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)

    runtime = ArtifactRuntime(paths)
    manifest = runtime.manifest
    tokenizer = AutoTokenizer.from_pretrained(manifest.model_name_or_path, trust_remote_code=False)
    if tokenizer.pad_token is None:
        if tokenizer.eos_token is not None:
            tokenizer.pad_token = tokenizer.eos_token
        elif tokenizer.unk_token is not None:
            tokenizer.pad_token = tokenizer.unk_token
    model = AutoModel.from_pretrained(manifest.model_name_or_path, trust_remote_code=False)
    if hasattr(model.config, "use_cache"):
        model.config.use_cache = False

    device_name = manifest.device.strip().lower()
    if device_name in ("", "auto"):
        device_name = "cuda" if torch.cuda.is_available() else "cpu"
    device = torch.device(device_name)
    model.to(device)
    model.train()

    batch_size = max(2, manifest.inference_batch_size)
    total_steps = max(1, math.ceil(len(pairs) / batch_size) * max(1, epochs))
    warmup_steps = int(total_steps * manifest.warmup_ratio)
    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=manifest.learning_rate,
        weight_decay=manifest.weight_decay,
    )
    scheduler = get_linear_schedule_with_warmup(optimizer, warmup_steps, total_steps)
    loss_fn = torch.nn.CrossEntropyLoss()

    steps = 0
    total_loss = 0.0
    started = time.time()
    rng = random.Random(seed)
    for _ in range(max(1, epochs)):
        rng.shuffle(pairs)
        for offset in range(0, len(pairs), batch_size):
            batch = pairs[offset : offset + batch_size]
            if len(batch) < 2:
                continue
            left_texts = [left for left, _ in batch]
            right_texts = [right for _, right in batch]
            left = tokenizer(
                left_texts,
                return_tensors="pt",
                padding=True,
                truncation=True,
                max_length=manifest.max_length,
            )
            right = tokenizer(
                right_texts,
                return_tensors="pt",
                padding=True,
                truncation=True,
                max_length=manifest.max_length,
            )
            left = {key: value.to(device) for key, value in left.items()}
            right = {key: value.to(device) for key, value in right.items()}

            optimizer.zero_grad(set_to_none=True)
            left_vec = encode_training_batch(model, left, manifest, torch)
            right_vec = encode_training_batch(model, right, manifest, torch)
            logits = left_vec @ right_vec.T
            logits = logits / manifest.contrastive_temperature
            labels = torch.arange(logits.size(0), device=device)
            loss = (loss_fn(logits, labels) + loss_fn(logits.T, labels)) * 0.5
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()

            steps += 1
            total_loss += float(loss.detach().cpu())
            if log_every > 0 and steps % log_every == 0:
                logging.getLogger("ml_service").info("train step=%d/%d loss=%.6f", steps, total_steps, total_loss / steps)

    model_dir = Path(output_dir) if output_dir is not None else paths.artifacts_dir / "model"
    model_dir.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(str(model_dir))
    tokenizer.save_pretrained(str(model_dir))

    manifest.encoder_backend = "transformers"
    manifest.model_name_or_path = str(model_dir)
    manifest.embedding_dim = int(getattr(model.config, "hidden_size", manifest.embedding_dim))
    manifest.model_version = f"{DEFAULT_MODEL_VERSION}-ft-{stable_hex(str(model_dir.resolve()))[:12]}"
    atomic_write_json(paths.manifest_path, manifest.to_payload())

    elapsed = max(0.001, time.time() - started)
    return {
        "dataset_path": str(dataset_path),
        "pairs": len(pairs),
        "epochs": max(1, epochs),
        "steps": steps,
        "mean_loss": round(total_loss / max(1, steps), 6),
        "elapsed_seconds": round(elapsed, 3),
        "model_dir": str(model_dir),
        "model_version": manifest.model_version,
        "device": str(device),
    }


def fit_centroids_from_dataset(
    index: KeenHashIndex,
    dataset_path: Path,
    *,
    clusters: int,
    iterations: int = 30,
    seed: int = 0,
    use_gpu: bool = False,
    limit_programs: int = 0,
    limit_functions: int = 0,
) -> dict[str, Any]:
    bundles = load_program_bundles(dataset_path, limit_programs)
    texts: list[str] = []
    for bundle in bundles:
        texts.extend(function_embedding_text(function, bundle) for function in bundle.functions)
        if limit_functions > 0 and len(texts) >= limit_functions:
            texts = texts[:limit_functions]
            break
    if not texts:
        raise ValueError("no functions were found for centroid fitting")
    embeddings = index.runtime.encoder.encode(texts)
    if embeddings.shape[0] < 2:
        raise ValueError("at least two function embeddings are required to fit centroids")
    cluster_count = min(max(2, int(clusters)), embeddings.shape[0])
    classifier = CentroidClassifier.fit(
        embeddings,
        clusters=cluster_count,
        iterations=iterations,
        seed=seed,
        use_gpu=use_gpu,
    )
    classifier.save(index.paths)
    index.runtime.reload()
    reindexed = index.reindex_all()
    return {
        "dataset_path": str(dataset_path),
        "programs": len(bundles),
        "functions": int(embeddings.shape[0]),
        "clusters": int(classifier.centroids.shape[0]),
        "centroids_path": str(index.paths.centroids_path),
        "labels_path": str(index.paths.centroid_labels_path),
        "reindexed_candidates": reindexed["candidate_count"],
    }


def ingest_programs_from_dataset(
    index: KeenHashIndex,
    dataset_path: Path,
    *,
    limit_programs: int = 0,
    replace: bool = False,
) -> dict[str, Any]:
    bundles = load_program_bundles(dataset_path, limit_programs)
    if replace:
        with index.lock:
            index.entries = {}
            index._rebuild_indexes_locked()
            index._persist_locked()
    last_binary_id = ""
    for bundle in bundles:
        result = index.ingest(bundle)
        last_binary_id = result["binary_id"]
    return {
        "dataset_path": str(dataset_path),
        "programs": len(bundles),
        "candidate_count": len(index.entries),
        "last_binary_id": last_binary_id,
    }


class App:
    def __init__(self, index: KeenHashIndex) -> None:
        self.index = index

    def health(self) -> dict[str, Any]:
        with self.index.lock:
            return self.index.runtime.health(len(self.index.entries))

    def share(self, payload: dict[str, Any]) -> dict[str, Any]:
        bundle = normalize_bundle(payload["program"])
        return self.index.ingest(bundle)

    def resolve(self, payload: dict[str, Any]) -> dict[str, Any]:
        bundle = normalize_bundle(payload["program"])
        topk = int(payload.get("topk") or bundle.topk or 10)
        return self.index.resolve(bundle, topk)


class RequestHandler(BaseHTTPRequestHandler):
    app: App

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        return json.loads(body or b"{}")

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            self._json(HTTPStatus.OK, self.app.health())
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        try:
            payload = self._read_json()
            if self.path == "/v1/share":
                self._json(HTTPStatus.OK, self.app.share(payload))
                return
            if self.path == "/v1/resolve":
                self._json(HTTPStatus.OK, self.app.resolve(payload))
                return
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
        except (KeyError, ValueError, json.JSONDecodeError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})

    def log_message(self, fmt: str, *args: Any) -> None:
        return


def build_server(
    bind: str,
    state_dir: Path | None,
    artifacts_dir: Path | None = None,
) -> ThreadingHTTPServer:
    host, port = bind.rsplit(":", 1)
    RequestHandler.app = App(KeenHashIndex(state_dir, artifacts_dir))
    return ThreadingHTTPServer((host, int(port)), RequestHandler)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="rz-silhouette KEENHash service")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--state-dir", default="")
    common.add_argument("--artifacts-dir", default="")
    common.add_argument("--log-level", default="INFO")

    subparsers = parser.add_subparsers(dest="command")

    serve = subparsers.add_parser("serve", parents=[common], help="Run the HTTP service")
    serve.add_argument("--bind", default="127.0.0.1:8080")

    init = subparsers.add_parser("init-artifacts", parents=[common], help="Create or refresh manifest.json")
    init.add_argument("--force", action="store_true")
    init.add_argument("--encoder-backend", default="transformers")
    init.add_argument("--model-name-or-path", default=DEFAULT_MODEL_NAME)

    train = subparsers.add_parser("train-encoder", parents=[common], help="Fine-tune the function encoder")
    train.add_argument("--dataset", required=True)
    train.add_argument("--output-dir", default="")
    train.add_argument("--epochs", type=int, default=1)
    train.add_argument("--limit-pairs", type=int, default=0)
    train.add_argument("--seed", type=int, default=0)
    train.add_argument("--log-every", type=int, default=10)

    fit = subparsers.add_parser("fit-centroids", parents=[common], help="Fit KEENHash structural centroids")
    fit.add_argument("--dataset", required=True)
    fit.add_argument("--clusters", type=int, default=4096)
    fit.add_argument("--iterations", type=int, default=30)
    fit.add_argument("--limit-programs", type=int, default=0)
    fit.add_argument("--limit-functions", type=int, default=0)
    fit.add_argument("--seed", type=int, default=0)
    fit.add_argument("--use-gpu", action="store_true")

    ingest = subparsers.add_parser("ingest-programs", parents=[common], help="Build or extend the corpus index")
    ingest.add_argument("--dataset", required=True)
    ingest.add_argument("--limit-programs", type=int, default=0)
    ingest.add_argument("--replace", action="store_true")

    health = subparsers.add_parser("health", parents=[common], help="Load artifacts and print health JSON")
    health.add_argument("--bind", default="")
    argv = sys.argv[1:]
    if not argv or argv[0].startswith("-"):
        argv = ["serve", *argv]
    return parser.parse_args(argv)


def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    state_dir = Path(args.state_dir) if args.state_dir else None
    artifacts_dir = Path(args.artifacts_dir) if args.artifacts_dir else None
    paths = build_runtime_paths(state_dir, artifacts_dir)

    if args.command == "init-artifacts":
        print(json.dumps(
            initialize_artifacts(
                paths,
                force=args.force,
                encoder_backend=args.encoder_backend,
                model_name_or_path=args.model_name_or_path,
            ),
            indent=2,
            sort_keys=True,
        ))
        return

    if args.command == "train-encoder":
        print(json.dumps(
            train_encoder(
                paths,
                Path(args.dataset),
                output_dir=Path(args.output_dir) if args.output_dir else None,
                epochs=args.epochs,
                limit_pairs=args.limit_pairs,
                seed=args.seed,
                log_every=args.log_every,
            ),
            indent=2,
            sort_keys=True,
        ))
        return

    if args.command == "fit-centroids":
        print(json.dumps(
            fit_centroids_from_dataset(
                KeenHashIndex(paths.state_dir, paths.artifacts_dir),
                Path(args.dataset),
                clusters=args.clusters,
                iterations=args.iterations,
                seed=args.seed,
                use_gpu=args.use_gpu,
                limit_programs=args.limit_programs,
                limit_functions=args.limit_functions,
            ),
            indent=2,
            sort_keys=True,
        ))
        return

    if args.command == "ingest-programs":
        print(json.dumps(
            ingest_programs_from_dataset(
                KeenHashIndex(paths.state_dir, paths.artifacts_dir),
                Path(args.dataset),
                limit_programs=args.limit_programs,
                replace=args.replace,
            ),
            indent=2,
            sort_keys=True,
        ))
        return

    if args.command == "health":
        index = KeenHashIndex(paths.state_dir, paths.artifacts_dir)
        print(json.dumps(index.runtime.health(len(index.entries)), indent=2, sort_keys=True))
        return

    server = build_server(args.bind, state_dir, artifacts_dir)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
