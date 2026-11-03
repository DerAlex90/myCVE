import httpx
import pytest

from mycve.server.feeds import BSI_METADATA, KEV_URL, FeedClient, FeedError


def test_official_cpe_dictionary_is_bounded_authenticated_and_complete():
    def handle(request):
        assert request.url.path == "/rest/json/cpes/2.0"
        assert request.url.params["keywordSearch"] == "Mozilla Firefox"
        assert request.headers["apiKey"] == "test-only-key"
        return httpx.Response(
            200,
            json={
                "totalResults": 1,
                "products": [{"cpe": {"cpeName": "cpe:2.3:a:mozilla:firefox:1.0:*:*:*:*:*:*:*"}}],
            },
        )

    with FeedClient(transport=httpx.MockTransport(handle), nvd_api_key="test-only-key") as client:
        assert len(client.cpe_dictionary("Mozilla Firefox")) == 1
    with FeedClient(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, json={"totalResults": 10001, "products": []})
        )
    ) as client:
        with pytest.raises(FeedError, match="unvollständig"):
            client.cpe_dictionary("Browser")


def test_osv_batch_pagination_retains_package_order():
    requests = []

    def handle(request):
        import json

        body = json.loads(request.content)
        requests.append(body)
        if len(requests) == 1:
            return httpx.Response(
                200,
                json={
                    "results": [{"vulns": [{"id": "GHSA-one"}], "next_page_token": "page-two"}, {}]
                },
            )
        assert body["queries"][0]["page_token"] == "page-two"
        return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-two"}]}]})

    packages = [("PyPI", "example", "1.0"), ("npm", "other", "2.0.0")]
    with FeedClient(transport=httpx.MockTransport(handle)) as client:
        result = client.osv_batch(packages)
    assert result[packages[0]] == ["GHSA-one", "GHSA-two"]
    assert result[packages[1]] == []
    assert requests[0]["queries"][0] == {
        "package": {"ecosystem": "PyPI", "name": "example"},
        "version": "1.0",
    }


def test_large_cpe_catalog_reads_later_pages_instead_of_missing_chrome_or_python():
    starts = []

    def handle(request):
        start = int(request.url.params["startIndex"])
        starts.append(start)
        size = 10000 if start == 0 else 1
        return httpx.Response(
            200,
            json={
                "totalResults": 10001,
                "products": [
                    {"cpe": {"cpeName": f"cpe:2.3:a:example:app:{index}:*:*:*:*:*:*:*"}}
                    for index in range(start, start + size)
                ],
            },
        )

    with FeedClient(transport=httpx.MockTransport(handle), sleep=lambda _: None) as client:
        assert len(client.cpe_dictionary("Example App")) == 10001
    assert starts == [0, 10000]


def test_truncated_batch_cannot_be_a_negative_match():
    with FeedClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"results": []}))
    ) as client:
        with pytest.raises(FeedError, match="Unvollständige"):
            client.osv_batch([("PyPI", "example", "1.0")])


def test_retries_and_redirects_are_bounded():
    attempts = []

    def handle(request):
        attempts.append(request)
        return httpx.Response(503)

    with FeedClient(transport=httpx.MockTransport(handle), sleep=lambda _: None) as client:
        with pytest.raises(FeedError):
            client.json("GET", KEV_URL)
    assert len(attempts) == 3
    with FeedClient(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(302, headers={"Location": "http://127.0.0.1"})
        )
    ) as client:
        with pytest.raises(FeedError):
            client.json("GET", KEV_URL)


def test_cve_program_uses_official_bucket():
    def handle(request):
        assert (
            str(request.url)
            == "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2024/3xxx/CVE-2024-3094.json"
        )
        return httpx.Response(200, json={"cveMetadata": {"cveId": "CVE-2024-3094"}})

    with FeedClient(transport=httpx.MockTransport(handle)) as client:
        assert client.cve("CVE-2024-3094")["cveMetadata"]["cveId"] == "CVE-2024-3094"
        with pytest.raises(FeedError):
            client.cve("../../etc/passwd")


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.test/a.json",
        "http://wid.cert-bund.de/.well-known/csaf/white/a.json",
        "https://wid.cert-bund.de/.well-known/csaf/green/a.json",
        "https://wid.cert-bund.de/.well-known/csaf/white/../green/a.json",
        "https://wid.cert-bund.de/.well-known/csaf/white/%2e%2e/a.json",
        "https://user@wid.cert-bund.de/.well-known/csaf/white/a.json",
    ],
)
def test_bsi_rejects_nonpublic_or_unsafe_urls(url):
    assert not FeedClient.public_bsi_url(url)


def test_bsi_metadata_and_document_tlp_both_checked():
    visited = []
    public = "https://wid.cert-bund.de/.well-known/csaf/white/feed.json"
    green = "https://wid.cert-bund.de/.well-known/csaf/green/feed.json"
    doc = "https://wid.cert-bund.de/.well-known/csaf/white/2026/advisory.json"

    def handle(request):
        url = str(request.url)
        visited.append(url)
        if url == BSI_METADATA:
            return httpx.Response(
                200,
                json={
                    "distributions": [
                        {
                            "rolie": {
                                "feeds": [
                                    {"url": public, "tlp_label": "WHITE"},
                                    {"url": green, "tlp_label": "GREEN"},
                                ]
                            }
                        }
                    ]
                },
            )
        if url == public:
            return httpx.Response(
                200,
                json={
                    "feed": {
                        "entry": [
                            {"category": [{"term": "CVE-2024-12345"}], "content": {"src": doc}}
                        ]
                    }
                },
            )
        assert url == doc
        return httpx.Response(200, json={"document": {"distribution": {"tlp": {"label": "GREEN"}}}})

    with FeedClient(transport=httpx.MockTransport(handle)) as client:
        documents, skipped = client.bsi_documents({"CVE-2024-12345"})
    assert documents == [] and skipped == 0
    assert green not in visited


def test_kev_count_must_match():
    with FeedClient(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, json={"count": 2, "vulnerabilities": []})
        )
    ) as client:
        with pytest.raises(FeedError):
            client.kev()
