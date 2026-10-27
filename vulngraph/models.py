"""Typed structures used internally by VulnGraph."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class Component:
    ref: str
    name: str
    version: str
    purl: str | None
    ecosystem: str | None
    direct: bool = False
    depth: int | None = None


@dataclass(frozen=True, slots=True)
class Advisory:
    identifier: str
    title: str
    refs: tuple[str, ...]
    cvss: float | None = None
    epss: float | None = None
    kev: bool = False
    aliases: tuple[str, ...] = ()
    link: str | None = None
    fixed_version: str | None = None
    source: str = "sbom"
    description: str = ""


@dataclass(frozen=True, slots=True)
class Inventory:
    name: str
    components: tuple[Component, ...]
    edges: tuple[tuple[str, str], ...]
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Context:
    internet_facing: bool = False
    business_criticality: int = 1  # 1..5


@dataclass(frozen=True, slots=True)
class Analysis:
    inventory: Inventory
    advisories: tuple[Advisory, ...]
    context: Context
    is_demo: bool = False
    data_sources: tuple[str, ...] = ()
    warnings: tuple[str, ...] = field(default_factory=tuple)
