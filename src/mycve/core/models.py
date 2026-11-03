# Copyright (c) 2026 Alexander Speka (DerAlex90)
# SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mycve.core.identity import canonical_ecosystem, package_identity


class Affectedness(StrEnum):
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    UNKNOWN = "unknown"


class Component(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=500)
    version: str | None = Field(default=None, max_length=300)
    ecosystem: str | None = Field(default=None, max_length=100)
    purl: str | None = Field(default=None, max_length=2000)
    cpe: str | None = Field(default=None, max_length=2000)
    vendor: str | None = Field(default=None, max_length=300)
    platform: str | None = Field(default=None, max_length=300)
    ref: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def normalize(self):
        self.version = self.version or None
        self.ecosystem = canonical_ecosystem(self.ecosystem or None)
        if self.purl:
            identity = package_identity(self.purl)
            if self.version and identity[2] and self.version != identity[2]:
                raise ValueError("Version und PURL-Version widersprechen sich")
            if self.ecosystem and identity[0] and self.ecosystem != identity[0]:
                raise ValueError("Ökosystem und PURL widersprechen sich")
            self.ecosystem = identity[0] or self.ecosystem
            self.name = identity[1]
            self.version = self.version or identity[2]
        return self


class MatchResult(BaseModel):
    status: Affectedness
    reason: str
    source: str = "OSV"
    confidence: Literal["exact", "candidate"] = "exact"
    fixed_versions: list[str] = Field(default_factory=list)
    patch_status: Literal["available", "unavailable", "unknown"] = "unknown"


class Priority(BaseModel):
    level: Literal["P0", "P1", "P2", "P3", "none"]
    score: int
    reasons: list[str]
