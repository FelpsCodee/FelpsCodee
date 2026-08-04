"""
Bot em Python que busca um CVE (vulnerabilidade real) na base pública da NVD
e atualiza o bloco correspondente no README.md automaticamente.

Executado diariamente pelo workflow .github/workflows/cve-of-day.yml
"""

import os
import re
import random
import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_random_cve() -> tuple[str, str]:
    try:
        start_index = random.randint(0, 500)
        response = requests.get(
            NVD_API,
            params={"resultsPerPage": 1, "startIndex": start_index},
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()

        vuln = data["vulnerabilities"][0]["cve"]
        cve_id = vuln["id"]

        descriptions = vuln.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d["lang"] == "en"),
            "Descrição indisponível.",
        )

        if len(description) > 260:
            description = description[:257].rsplit(" ", 1)[0] + "..."

        return cve_id, description

    except Exception as exc: 
        return "N/A", f"Não foi possível buscar o CVE hoje ({exc})."


def update_readme(cve_id: str, description: str, path: str = "README.md") -> None:
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    new_block = (
        "<!--CVE:START-->\n"
        f"** CVE do dia:** `{cve_id}`\n"
        f"> {description}\n"
        "<!--CVE:END-->"
    )

    updated = re.sub(
        r"<!--CVE:START-->.*<!--CVE:END-->",
        new_block,
        content,
        flags=re.DOTALL,
    )

    with open(path, "w", encoding="utf-8") as f:
        f.write(updated)


if __name__ == "__main__":
    cve_id, description = fetch_random_cve()
    update_readme(cve_id, description)
    print(f"README atualizado com {cve_id}")
