"""Evaluation regression: the graph detector must beat the naive baseline."""
import pathlib

import yaml

from ksa.collector.directory_collector import DirectoryCollector
from ksa.evaluation import detector_positives, naive_baseline, score

EVAL = pathlib.Path(__file__).parent / "fixtures" / "eval"


def _load():
    snap = DirectoryCollector(EVAL).collect()
    labels = yaml.safe_load((EVAL / "labels.yaml").read_text())
    return snap, set(labels["positive"]), set(labels["negative"])


def test_graph_has_no_false_positives():
    snap, pos, neg = _load()
    m = score(detector_positives(snap), pos, neg)
    assert m.fp == 0
    assert m.precision == 1.0


def test_graph_full_recall():
    snap, pos, neg = _load()
    m = score(detector_positives(snap), pos, neg)
    assert m.recall == 1.0


def test_graph_beats_naive_f1():
    snap, pos, neg = _load()
    graph = score(detector_positives(snap), pos, neg)
    naive = score(naive_baseline(snap), pos, neg)
    assert graph.f1 >= naive.f1
    assert naive.fp > 0  # the naive baseline should over-flag on this dataset
