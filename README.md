**PrivAI is a fully local research and RAG system built for people who want deep research capabilities without sending their data to external services.
**
Most local AI tools feel slow because they try to do everything with a single large model. PrivAI takes a different approach. It splits the workload across multiple models and manages them intelligently so your system stays responsive.


How it works
PrivAI runs a traffic control system inside the worker node that routes tasks based on what actually needs to be done.
1. Fast mode using a lightweight model
Llama 3.2 1B is used for tasks that need speed rather than deep reasoning.
This includes browsing and scraping multiple websites in parallel, quick fact checking, and collecting raw context for later processing.
Because this model is lightweight, it stays fast and does not block the GPU.


3. Heavy mode for deep thinking
Qwen 2.5 32B or 14B is used for tasks that require real reasoning.
This includes synthesizing final answers, analyzing PDFs, and working with long context windows.
This is where the high quality responses come from.


3. Smart queue system
When the GPU is busy running a heavy task, new requests are queued instead of being executed immediately.
This prevents VRAM exhaustion and keeps the system stable even under load.


Features
Full local privacy
Chat history is encrypted with AES 256 at rest. Nothing is sent to third party servers.
Deep research agent
The system can autonomously search the web using Serper, scrape content, and synthesize answers with citations.
PDF RAG
Upload documents and chat with them using local embeddings.
Vision support
Images can be dropped into the chat and processed using OCR.
Voice output
Responses can be generated as speech using text to speech.




Hardware requirements
This runs locally, so hardware matters.
Recommended setup for deep research
GPU
NVIDIA RTX 3090 , 4090, 5080/5090 with 24GB of VRAM (16 minimum for 14b model with deep research)
RAM - 32GB or more system memory



Models - Qwen 2.5 32B and Llama 3.2 1B

Minimum setup
GPU
NVIDIA RTX 3060 or 4070 with 12GB of VRAM

RAM -16GB system memory

Models
Qwen 2.5 14B in quantized form and Llama 3.2 1B
The minimum setup works, but heavier research tasks benefit significantly from more VRAM.


Installation
1. Prerequisites
Ollama must be installed and running.
Pull the required models.
ollama pull qwen2.5:32b
ollama pull llama3.2:1b
ollama pull nomic-embed-text

Tesseract OCR must also be installed for image analysis features.


2. Clone and setup
git clone https://github.com/YOUR_USERNAME/PrivAI.git
cd PrivAI
pip install -r requirements.txt


3. Configuration
Rename .env.example to .env and set the following values.
SERPER_API_KEY
Used for Google search results. A free key can be obtained from serper.dev.
WORKER_SECRET_KEY
A secure secret used to authenticate the worker with the server.

4. Running the system
Two terminal windows are required.
Terminal one runs the server.
python app.py


Terminal two runs the AI worker.
python worker.py


Once both are running, open a browser and go to:
http://localhost:10000

Architecture
Backend - FastAPI with WebSockets handling authentication, encryption, and session state.
Worker - Async Python with Ollama handling scraping, queue management, and inference.
Frontend -Vanilla JavaScript with Tailwind for a simple dark mode interface.
Database - Firebase Firestore used for encrypted storage.

Contributing

Contributions are welcome, especially for improving scraping reliability, optimizing queue behavior, or adding support for additional local vector stores such as ChromaDB.
