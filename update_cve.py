"""
Bot em Python que busca um CVE na base pública da NVD
e atualiza o bloco correspondente no README.md automaticamente.
"""

import os
import re
import random
import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_random_cve() -> tuple[str, str, str]:
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    
    nvd_api_key = os.getenv("NVD_API_KEY")
    if nvd_api_key:
        headers["apiKey"] = nvd_api_key

    try:
        start_index = random.randint(0, 50)
        params = {
            "resultsPerPage": 1,
            "startIndex": start_index
        }
        
        response = requests.get(
            NVD_API,
            headers=headers,
            params=params,
            timeout=15
        )
        response.raise_for_status()
        data = response.json()

        vuln = data["vulnerabilities"][0]["cve"]
        cve_id = vuln["id"]
        cve_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        descriptions = vuln.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d["lang"] == "en"),
            "Descrição indisponível."
        )

        if len(description) > 260:
            description = description[:257].rsplit(" ", 1)[0] + "..."

        return cve_id, description, cve_url

    except Exception as exc: 
        return "N/A", f"Não foi possível buscar o CVE hoje ({exc}).", "#"


def update_readme(cve_id: str, description: str, cve_url: str, path: str = "README.md") -> None:
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

  
    if cve_id != "N/A":
        cve_line = f"**CVE do dia:** [{cve_id}]({cve_url})\n"
    else:
        cve_line = f"**CVE do dia:** `{cve_id}`\n"

    new_block = (
        "<!--CVE:START-->\n"
        f"{cve_line}"
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
    cve_id, description, cve_url = fetch_random_cve()
    update_readme(cve_id, description, cve_url)
    print(f"README atualizado com {cve_id}")