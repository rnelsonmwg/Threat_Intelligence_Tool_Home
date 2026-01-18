# Threat Intelligence IOC/TTP Report Parser and Distributor Tool

Python Files Included:
  -  env_tool_tester.py:
      - environment tool tester; verifies all prerequisite installs are complete
  -  threat_intel_parser_tool_cli.py:
      -  CLI version of the parser tool
 

The CLI version of the tool instructions:

Options:
-  -h, --help            show this help message and exit
-  -f FILE, --file FILE  Text file containing URLs (one per line)
-  -u URL, --url URL     Single URL to process
-  -p PDFS [PDFS ...], --pdfs PDFS [PDFS ...]
                        PDF files to process
-  -o OUTPUT, --output OUTPUT
                        Output directory for CSV files (default: current
                        directory)
-  --model MODEL         Ollama model name (default: llama3.2)

Examples:
  - Process URL list
    - python3 threat_intel_parser_tool_cli.py -f urls.txt -o ./reports
  
  - Process single URL
    - python3 threat_intel_parser_tool_cli.py -u https://blog.com/threat-report -o ./reports
  
  - Process PDF files
    - python3 threat_intel_parser_tool_cli.py -p report1.pdf report2.pdf -o ./reports
  
  - Custom LLM model
    - python3 threat_intel_parser_tool_cli.py -f urls.txt --model llama3.1 -o ./reports

Output Files:
  - threat_intel_summary_TIMESTAMP.csv    (High-level overview)
  - threat_intel_iocs_TIMESTAMP.csv       (IOC database)
  - threat_intel_ttps_TIMESTAMP.csv       (Framework mappings)
  - threat_intel_detailed_TIMESTAMP.csv   (Complete report)

Pre-Requisites to using the threat intelligence parser:
  - Install Python version 3
    - sudo apt install python3
  
  - Install a Virtual Environment
    - sudo apt install python3.xx-venv
    - python3 -m venv .venv
    - source .venv/bin/activate
  
  - Install Ollama Server
    - curl -fsSL https://ollama.com/install.sh | sh 
 
  - Install additional python libraries
    - pip3 install ollama pdfplumber requests numpy beautifulsoup4 pydantic
  
  - What these libraries do:
      - ollama: Connects the script to your local AI models.
      - pdfplumber: Allows the script to "read" and extract text from PDF research papers.
      - requests & beautifulsoup4: Used to scrape and clean text from security blog URLs.
      - numpy: Handles the math for "RAG" (calculating how relevant a piece of text is to your search).
      - pydantic: Ensures the output follows a strict STIX-compatible structure.
  
  - Pull a capable model
      - ollama pull llama3.2
      - ollama pull nomic-embed-text
    
  - Run the environment tool tester to verify all pre-requisites are installed before running the tool. This will help verify the environment is all set for the tool to run without errors.
