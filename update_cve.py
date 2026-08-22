"""
Salve em: scripts/update_cve.py

Busca no NVD (National Vulnerability Database) as CVEs publicadas nos
ultimos dias e injeta a de maior severidade CVSS entre os marcadores
<!--CVE:START--> e <!--CVE:END--> do README.md.
"""

import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
README = Path("README.md")
JANELA_DIAS = 3
TIMEOUT = 30


def buscar_cves(dias: int = JANELA_DIAS) -> list[dict]:
    """Retorna as CVEs publicadas na janela de tempo informada."""
    fim = datetime.now(timezone.utc)
    inicio = fim - timedelta(days=dias)

    params = {
        "pubStartDate": inicio.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": fim.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 200,
    }

    resposta = requests.get(NVD_API, params=params, timeout=TIMEOUT)
    resposta.raise_for_status()
    return resposta.json().get("vulnerabilities", [])


def extrair_score(cve: dict) -> float:
    """Le o score CVSS, tentando v3.1, v3.0 e v2 nessa ordem."""
    metricas = cve.get("metrics", {})
    for chave in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entradas = metricas.get(chave)
        if entradas:
            return float(entradas[0]["cvssData"]["baseScore"])
    return 0.0


def extrair_descricao(cve: dict) -> str:
    """Pega a descricao em ingles e limita o tamanho para caber no README."""
    for item in cve.get("descriptions", []):
        if item.get("lang") == "en":
            texto = " ".join(item["value"].split())
            return texto[:220] + "..." if len(texto) > 220 else texto
    return "Sem descricao disponivel."


def severidade(score: float) -> str:
    if score >= 9.0:
        return "CRITICA"
    if score >= 7.0:
        return "ALTA"
    if score >= 4.0:
        return "MEDIA"
    return "BAIXA"


def montar_bloco(cve: dict, score: float) -> str:
    cve_id = cve["id"]
    data = cve.get("published", "")[:10]
    url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

    return (
        f"<!--CVE:START-->\n"
        f"**CVE do dia:** [{cve_id}]({url}) — "
        f"`CVSS {score:.1f}` · **{severidade(score)}** · publicada em {data}\n"
        f">\n"
        f"> {extrair_descricao(cve)}\n"
        f"<!--CVE:END-->"
    )


def main() -> int:
    try:
        vulnerabilidades = buscar_cves()
    except requests.RequestException as erro:
        print(f"[!] Falha ao consultar o NVD: {erro}", file=sys.stderr)
        return 1

    if not vulnerabilidades:
        print("[!] Nenhuma CVE retornada na janela consultada.", file=sys.stderr)
        return 0

    candidatas = [(item["cve"], extrair_score(item["cve"])) for item in vulnerabilidades]
    cve, score = max(candidatas, key=lambda par: par[1])

    conteudo = README.read_text(encoding="utf-8")
    novo = re.sub(
        r"<!--CVE:START-->.*?<!--CVE:END-->",
        montar_bloco(cve, score).replace("\\", "\\\\"),
        conteudo,
        flags=re.DOTALL,
    )

    if novo == conteudo:
        print("[=] README ja esta atualizado.")
        return 0

    README.write_text(novo, encoding="utf-8")
    print(f"[+] README atualizado com {cve['id']} (CVSS {score:.1f})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
