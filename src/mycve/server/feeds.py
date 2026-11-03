# Copyright (c) 2026 Alexander Speka (DerAlex90)
# SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

"""Bounded official feed clients. Feed URLs never come from API input."""

import io
import json
import re
import time
from urllib.parse import quote, urlparse

import httpx
import ijson

from mycve import __version__

OSV_BASE = "https://api.osv.dev/v1"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_MIRROR_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
BSI_METADATA = "https://wid.cert-bund.de/.well-known/csaf/provider-metadata.json"
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")
PUBLIC_TLP = {"WHITE", "CLEAR"}


class FeedError(RuntimeError):
    pass


class _StreamReader(io.RawIOBase):
    """Adapt decompressed HTTP chunks without loading an entire ROLIE feed."""

    def __init__(self, chunks, limit=512_000_000):
        self.chunks = iter(chunks)
        self.buffer = b""
        self.total = 0
        self.limit = limit

    def readable(self):
        return True

    def readinto(self, target):
        if not self.buffer:
            self.buffer = next(self.chunks, b"")
            self.total += len(self.buffer)
            if self.total > self.limit:
                raise FeedError("BSI ROLIE-Feed überschreitet 512 MB")
        count = min(len(target), len(self.buffer))
        target[:count] = self.buffer[:count]
        self.buffer = self.buffer[count:]
        return count


class FeedClient:
    def __init__(self, *, timeout=40, nvd_api_key="", transport=None, sleep=time.sleep):
        self.client = httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            transport=transport,
            headers={"User-Agent": f"myCVE/{__version__} (+https://github.com/DerAlex90/myCVE)"},
        )
        self.nvd_api_key = nvd_api_key
        self.sleep = sleep
        self.last_nvd = 0.0
        self.kev_url = KEV_URL

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.client.close()

    def json(self, method: str, url: str, *, body=None, headers=None, params=None, optional=False):
        for attempt in range(3):
            try:
                with self.client.stream(
                    method, url, json=body, headers=headers, params=params
                ) as response:
                    if optional and response.status_code == 404:
                        return None
                    if response.status_code == 429 or response.status_code >= 500:
                        if attempt < 2:
                            retry_after = response.headers.get("retry-after", "")
                            delay = (
                                min(float(retry_after), 30) if retry_after.isdigit() else 2**attempt
                            )
                            self.sleep(delay)
                            continue
                    response.raise_for_status()
                    content = bytearray()
                    for chunk in response.iter_bytes():
                        content.extend(chunk)
                        if len(content) > 32_000_000:
                            raise FeedError("Quelldokument überschreitet 32 MB")
                    result = json.loads(content)
                    if not isinstance(result, dict):
                        raise FeedError("Quelle liefert kein JSON-Objekt")
                    return result
            except (httpx.HTTPError, json.JSONDecodeError) as exc:
                if attempt == 2 or isinstance(exc, httpx.HTTPStatusError):
                    code = (
                        f"HTTP {exc.response.status_code}"
                        if isinstance(exc, httpx.HTTPStatusError)
                        else type(exc).__name__
                    )
                    raise FeedError(f"{urlparse(url).hostname}: {code}") from exc
                self.sleep(2**attempt)
        raise FeedError("Quelle nach mehreren Versuchen nicht erreichbar")

    def osv_batch(self, packages: list[tuple[str, str, str | None]]) -> dict[tuple, list[str]]:
        observations: dict[tuple, list[str]] = {}
        for offset in range(0, len(packages), 100):
            batch = packages[offset : offset + 100]
            pending = [(item, None) for item in batch]
            for _ in range(100):
                queries = []
                for (ecosystem, name, version), token in pending:
                    query: dict = {"package": {"ecosystem": ecosystem, "name": name}}
                    if version:
                        query["version"] = version
                    if token:
                        query["page_token"] = token
                    queries.append(query)
                response = self.json("POST", OSV_BASE + "/querybatch", body={"queries": queries})
                results = response.get("results", [])
                if len(results) != len(pending):
                    raise FeedError("OSV: Unvollständige Batch-Antwort")
                next_pending = []
                for (package, _), result in zip(pending, results, strict=True):
                    ids = observations.setdefault(package, [])
                    ids.extend(item["id"] for item in result.get("vulns", []))
                    if len(ids) > 10000:
                        raise FeedError("OSV: Zu viele Meldungen für ein Paket; Version ergänzen")
                    if result.get("next_page_token"):
                        next_pending.append((package, result["next_page_token"]))
                pending = next_pending
                if not pending:
                    break
            else:
                raise FeedError("OSV: Paginierungslimit erreicht")
        return {package: sorted(set(ids)) for package, ids in observations.items()}

    def osv_details(self, advisory_id: str) -> dict:
        if not re.fullmatch(r"[A-Za-z0-9_.:+-]{1,200}", advisory_id):
            raise FeedError("Ungültige OSV-ID")
        return self.json("GET", OSV_BASE + "/vulns/" + quote(advisory_id, safe=""))

    def kev(self) -> dict:
        try:
            catalog = self.json("GET", KEV_URL)
            self.kev_url = KEV_URL
        except FeedError:
            catalog = self.json("GET", KEV_MIRROR_URL)
            self.kev_url = KEV_MIRROR_URL
        if "vulnerabilities" not in catalog or catalog.get("count") != len(
            catalog["vulnerabilities"]
        ):
            raise FeedError("CISA KEV: Katalog unvollständig")
        return catalog

    def nvd(self, cve_id: str) -> dict | None:
        if not CVE_PATTERN.fullmatch(cve_id):
            raise FeedError("Ungültige CVE-ID")
        interval = 0.7 if self.nvd_api_key else 6.1
        remaining = interval - (time.monotonic() - self.last_nvd)
        if remaining > 0:
            self.sleep(remaining)
        self.last_nvd = time.monotonic()
        result = self.json(
            "GET",
            NVD_URL,
            params={"cveId": cve_id},
            headers={"apiKey": self.nvd_api_key} if self.nvd_api_key else {},
        )
        items = result.get("vulnerabilities", [])
        return items[0]["cve"] if items else None

    def nvd_cpe(self, cpe: str) -> list[dict]:
        from mycve.core.cpe import parse_cpe

        fields = parse_cpe(cpe)
        if any(value in {"*", "-"} for value in fields[:4]):
            raise FeedError("NVD-CPE-Abgleich benötigt Hersteller, Produkt und konkrete Version")
        results: list[dict] = []
        for start in range(0, 10000, 2000):
            interval = 0.7 if self.nvd_api_key else 6.1
            remaining = interval - (time.monotonic() - self.last_nvd)
            if remaining > 0:
                self.sleep(remaining)
            self.last_nvd = time.monotonic()
            page = self.json(
                "GET",
                NVD_URL,
                params={
                    "cpeName": cpe,
                    "isVulnerable": "",
                    "startIndex": start,
                    "resultsPerPage": 2000,
                },
                headers={"apiKey": self.nvd_api_key} if self.nvd_api_key else {},
            )
            items = page.get("vulnerabilities", [])
            total = page.get("totalResults")
            if not isinstance(total, int) or (not items and total > start):
                raise FeedError("NVD: Unvollständige CPE-Abfrage")
            results.extend(item["cve"] for item in items)
            if len(results) >= total:
                return results
        raise FeedError("NVD: CPE-Abfrage überschreitet 10000 Treffer")

    def cpe_dictionary(self, name: str) -> list[dict]:
        """Discover products from the official dictionary, never from CVE keyword hits."""
        if not 2 <= len(name) <= 300:
            raise FeedError("Produktname für CPE-Suche ist ungültig")
        entries: list[dict] = []
        expected = None
        for start in range(0, 50000, 10000):
            interval = 0.7 if self.nvd_api_key else 6.1
            remaining = interval - (time.monotonic() - self.last_nvd)
            if remaining > 0:
                self.sleep(remaining)
            self.last_nvd = time.monotonic()
            page = self.json(
                "GET",
                NVD_CPE_URL,
                params={"keywordSearch": name, "resultsPerPage": 10000, "startIndex": start},
                headers={"apiKey": self.nvd_api_key} if self.nvd_api_key else {},
            )
            products, total = page.get("products"), page.get("totalResults")
            if (
                not isinstance(products, list)
                or not isinstance(total, int)
                or total > 50000
                or len(products) != min(10000, max(total - start, 0))
                or (expected is not None and expected != total)
            ):
                raise FeedError("NVD-CPE: Produktsuche unvollständig oder über 50000 Treffer")
            expected = total
            if any(
                not isinstance(item.get("cpe"), dict) or not item["cpe"].get("cpeName")
                for item in products
            ):
                raise FeedError("NVD-CPE: Ungültiger Produkteintrag")
            entries.extend(item["cpe"] for item in products)
            if len(entries) == total:
                return entries
        raise FeedError("NVD-CPE: Paginierungslimit erreicht")

    def cve(self, cve_id: str) -> dict | None:
        if not CVE_PATTERN.fullmatch(cve_id):
            raise FeedError("Ungültige CVE-ID")
        _, year, number = cve_id.split("-")
        bucket = number[:-3] + "xxx"
        url = f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{bucket}/{cve_id}.json"
        return self.json("GET", url, optional=True)

    @staticmethod
    def public_bsi_url(url: str, *, feed=False) -> bool:
        parsed = urlparse(url)
        return (
            parsed.scheme == "https"
            and parsed.hostname == "wid.cert-bund.de"
            and parsed.port in {None, 443}
            and not parsed.username
            and not parsed.password
            and parsed.path.startswith("/.well-known/csaf/white/")
            and ".." not in parsed.path
            and "%" not in parsed.path
            and not parsed.query
            and not parsed.fragment
            and parsed.path.endswith(".json")
        )

    def bsi_documents(
        self, cve_ids: set[str], *, known_urls: list[str] | None = None, limit=50
    ) -> tuple[list[tuple[str, dict]], int]:
        metadata = self.json("GET", BSI_METADATA)
        feeds = {
            feed["url"]
            for dist in metadata.get("distributions", [])
            for feed in dist.get("rolie", {}).get("feeds", [])
            if feed.get("tlp_label", "").upper() in PUBLIC_TLP
            and self.public_bsi_url(feed.get("url", ""), feed=True)
        }
        if not feeds:
            raise FeedError("BSI: Keine öffentlichen Feeds in Provider-Metadaten")
        candidates = {url: "" for url in known_urls or [] if self.public_bsi_url(url)}
        for url in sorted(feeds):
            for entry in self.bsi_entries(url):
                aliases = {category.get("term") for category in entry.get("category", [])}
                content_url = entry.get("content", {}).get("src", "")
                if aliases & cve_ids and self.public_bsi_url(content_url):
                    candidates[content_url] = entry.get("updated", "")
        ordered = sorted(candidates, key=lambda url: candidates[url], reverse=True)
        documents = []
        for url in ordered[:limit]:
            document = self.json("GET", url)
            label = (
                document.get("document", {})
                .get("distribution", {})
                .get("tlp", {})
                .get("label", "")
                .upper()
            )
            if label in PUBLIC_TLP:
                documents.append((url, document))
        return documents, max(0, len(ordered) - limit)

    def bsi_entries(self, url: str):
        if not self.public_bsi_url(url, feed=True):
            raise FeedError("BSI: Nicht öffentlicher Feed abgelehnt")
        try:
            with self.client.stream("GET", url) as response:
                response.raise_for_status()
                with io.BufferedReader(
                    _StreamReader(response.iter_bytes(chunk_size=65536))
                ) as reader:
                    yield from ijson.items(reader, "feed.entry.item")
        except (httpx.HTTPError, ijson.JSONError) as exc:
            raise FeedError("BSI ROLIE-Feed konnte nicht vollständig gelesen werden") from exc
