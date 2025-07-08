# 🧠 SOC Log Analyzer (Agentic AI-Powered)

A full-stack AI-powered SOC (Security Operations Center) log analysis tool that uses a local LLM (via Ollama) to classify, explain, and recommend remediations for endpoint behavior logs—acting like a senior cyber analyst.

## 🛠️ Project Structure

├── mcp_server.py # FastAPI MCP backend server
├── log_query_client.py # CLI tool for querying and analyzing logs
├── log_query_webui.html # Web UI frontend (static HTML + JS)
├── Modelfile # Ollama Modelfile for LLM definition
├── /logs # Folder for JSON log files (CrowdStrike-style)

## 🌐 MCP Server

The `mcp_server.py` file launches a FastAPI server with the following endpoints:

- `POST /query` → Search logs based on `hostname`, `cid`, or `timestamp`.
- `POST /analyze` → Sends a specific log file to the local Ollama model (`soc-llm-mcp`) for AI-based threat analysis and recommendations.

### 🔧 Configuration

Edit the `LOG_DIR`, `OLLAMA_URL`, and `OLLAMA_MODEL` values inside `mcp_server.py`:

```python
LOG_DIR = r"C:\\Path\\To\\Your\\logs"
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "soc-llm-mcp:latest"

uvicorn mcp_server:app --reload --host 0.0.0.0 --port 8000


💻 CLI Client
Use log_query_client.py to interact with the MCP server from the terminal.

bash
Copy
Edit
python log_query_client.py

->Prompts for filters like hostname, cid, and timestamp
->Lists matching logs
->Sends selected log to the backend for AI analysis
->Displays structured Markdown verdict using rich


🌐 Web UI
Open log_query_webui.html in a browser to use the UI version:
->Submit hostname, CID, or timestamp filters.
->View matching logs in a dropdown.
->Send logs for analysis.
->View the AI verdict in a styled terminal-like interface.
->This frontend talks directly to http://localhost:8000 (make sure MCP is running).

📁 Logs
->There is log generator script  log_generator.py
-> # Config 
->OUTPUT_DIR = r"C:\\Users\\Palla\\aimlmcpser\\logs"
-> sample log is provided

-> For Command Line

