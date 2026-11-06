"""MiniLM sentence embeddings (via fastembed: ONNX runtime, no PyTorch).

Each text becomes a 384-number vector that represents its meaning. Vectors are
L2-normalised, so the dot product of two vectors is their cosine similarity.
"""

import numpy as np

from app import config


class Embedder:
    def __init__(self, model_name: str = config.EMBED_MODEL, cache_dir=config.MODEL_CACHE_DIR):
        self.model_name = model_name
        self.cache_dir = str(cache_dir)
        self._model = None

    def _load(self):
        if self._model is None:
            from fastembed import TextEmbedding  # heavy import, only when needed
            self._model = TextEmbedding(self.model_name, cache_dir=self.cache_dir)
        return self._model

    def embed(self, texts: list[str]) -> np.ndarray:
        if not texts:
            return np.zeros((0, 0), dtype=np.float32)
        vectors = np.asarray(list(self._load().embed(texts)), dtype=np.float32)
        norms = np.linalg.norm(vectors, axis=1, keepdims=True)
        return vectors / np.where(norms == 0, 1, norms)
