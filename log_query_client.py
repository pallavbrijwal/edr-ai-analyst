import requests
from rich import print
from rich.prompt import Prompt

MCP_QUERY_URL = "http://127.0.0.1:8000/query"
MCP_ANALYZE_URL = "http://127.0.0.1:8000/analyze"

def get_filters():
    hostname = Prompt.ask("🔎 Enter hostname (or leave blank)", default="")
    cid = Prompt.ask("🆔 Enter CID (or leave blank)", default="")
    timestamp = Prompt.ask("⏰ Enter timestamp (or leave blank)", default="")
    return {
        "hostname": hostname.strip() or None,
        "cid": cid.strip() or None,
        "timestamp": timestamp.strip() or None
    }

def query_logs(params):
    try:
        res = requests.post(MCP_QUERY_URL, json=params)
        res.raise_for_status()
        matches = res.json().get("matches", [])
        if not matches:
            print("[yellow]No logs found matching the query.[/yellow]")
            return []

        print(f"\n[green]✅ Found {len(matches)} matching logs:[/green]")
        for i, match in enumerate(matches, 1):
            print(f"[cyan]{i}.[/cyan] File: {match['file']} | Hostname: {match['log']['device']['hostname']}")
        return matches

    except Exception as e:
        print(f"[red]❌ Query failed:[/red] {e}")
        return []

def select_log(matches):
    index = Prompt.ask("📂 Select file number to analyze", choices=[str(i+1) for i in range(len(matches))])
    return matches[int(index)-1]['file']

def analyze_log(file_name):
    print(f"\n🚀 Sending [bold]{file_name}[/bold] to MCP for analysis...")
    try:
        res = requests.post(MCP_ANALYZE_URL, json={"file": file_name})
        res.raise_for_status()
        verdict = res.json().get("verdict", "No verdict returned.")
        print("\n[bold green]🧠 AI Verdict:[/bold green]\n")
        print(verdict)
    except Exception as e:
        print(f"[red]❌ Analysis failed:[/red] {e}")

def main():
    print("[bold cyan]SOC Log Analyzer CLI[/bold cyan]")
    filters = get_filters()
    matches = query_logs(filters)
    if matches:
        file_name = select_log(matches)
        analyze_log(file_name)

if __name__ == "__main__":
    main()
