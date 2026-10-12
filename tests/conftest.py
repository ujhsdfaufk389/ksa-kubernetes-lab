"""Shared pytest fixtures — load the deterministic mini-cluster offline."""
import pathlib

import pytest

from ksa.analyzer import Analyzer
from ksa.collector.directory_collector import DirectoryCollector
from ksa.graph.graph_builder import GraphBuilder
from ksa.permissions import PermissionResolver

FIXTURE_DIR = pathlib.Path(__file__).parent / "fixtures" / "mini"


@pytest.fixture(scope="session")
def snapshot():
    return DirectoryCollector(FIXTURE_DIR).collect()


@pytest.fixture
def resolver(snapshot):
    return PermissionResolver(snapshot)


@pytest.fixture
def effective(resolver):
    return resolver.resolve_all()


@pytest.fixture
def graph(snapshot):
    return GraphBuilder(snapshot).build()


@pytest.fixture
def analyzer(snapshot):
    return Analyzer(snapshot)


@pytest.fixture
def findings(analyzer):
    return analyzer.findings()
