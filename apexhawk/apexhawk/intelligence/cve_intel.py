"""CVEIntelligenceManager - read-only lookups against public CVE data (NVD).

This performs OSINT only: it queries the public National Vulnerability
Database for CVE metadata (description, CVSS, references). It never fetches or
produces exploit code.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None  # type: ignore

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CVEIntelligenceManager:
    def __init__(self, timeout: int = 15) -> None:
        self.timeout = timeout

    def _query(self, params: Dict[str, Any]) -> Dict[str, Any]:
        if requests is None:
            return {"error": "the 'requests' package is not installed"}
        try:
            resp = requests.get(NVD_ENDPOINT, params=params, timeout=self.timeout,
                                headers={"User-Agent": "ApexHawk-CVEIntel"})
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            return {"error": f"NVD request failed: {exc}"}

    @staticmethod
    def _simplify(item: Dict[str, Any]) -> Dict[str, Any]:
        cve = item.get("cve", {})
        descs = cve.get("descriptions", [])
        description = next((d.get("value") for d in descs if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        score = None
        severity = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                data = metrics[key][0].get("cvssData", {})
                score = data.get("baseScore")
                severity = data.get("baseSeverity") or metrics[key][0].get("baseSeverity")
                break
        return {
            "id": cve.get("id"),
            "published": cve.get("published"),
            "cvss": score,
            "severity": severity,
            "description": (description or "")[:400],
            "references": [r.get("url") for r in cve.get("references", [])][:6],
        }

    def get(self, cve_id: str) -> Dict[str, Any]:
        data = self._query({"cveId": cve_id})
        if "error" in data:
            return data
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return {"error": f"no data for {cve_id}"}
        return self._simplify(vulns[0])

    def search(self, keyword: str, limit: int = 10) -> Dict[str, Any]:
        data = self._query({"keywordSearch": keyword, "resultsPerPage": limit})
        if "error" in data:
            return data
        vulns = data.get("vulnerabilities", [])
        return {
            "keyword": keyword,
            "total": data.get("totalResults", len(vulns)),
            "results": [self._simplify(v) for v in vulns[:limit]],
        }
