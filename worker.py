"""
PrivAI Worker Node (Open Source Edition)
----------------------------------------
Hardware Requirements:
- GPU: 24GB VRAM recommended (RTX 3090/4090/5090) for full performance.
       Minimum 12GB VRAM (RTX 3060/4070) if reducing token limits or downgrading models.
- RAM: 32GB+ System RAM.

Ollama Models Required:
- 'qwen2.5:32b' (Deep Think / Advanced)
- 'qwen2.5:14b' (Basic)
- 'llama3.2:1b' (US Lite / Fast Research)

Environment Variables:
- RENDER_SERVER_URL: WebSocket URL of your backend.
- SERPER_API_KEY: API Key from serper.dev.
- WORKER_SECRET_KEY: Shared secret for authentication.
"""

import asyncio
import websockets
import json
import base64
import fitz
import numpy as np
from PIL import Image
import pytesseract
from openai import AsyncOpenAI, OpenAI
from sklearn.metrics.pairwise import cosine_similarity
from typing import Dict, Any
import datetime
import io
import os
import requests
from bs4 import BeautifulSoup
from ddgs import DDGS
import time
import secrets
import socket
import ipaddress
import re
import random
from urllib.parse import urlparse, quote_plus
from cryptography.fernet import Fernet
import hashlib
import edge_tts
import tempfile

if os.name == 'nt':
    pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

KB_FOLDER = "knowledge_base"

RENDER_SERVER_URL = os.environ.get("RENDER_SERVER_URL", "ws://localhost:10000/ws/worker")
SERPER_API_KEY = os.environ.get("SERPER_API_KEY")
WORKER_SECRET_KEY = os.environ.get("WORKER_SECRET_KEY", "dev_secret_key")

if not SERPER_API_KEY:
    print("WARNING: SERPER_API_KEY not found. Web search capabilities will be limited.")

client = AsyncOpenAI(base_url='http://localhost:11434/v1', api_key='ollama', timeout=300.0)
embedding_model_name = 'nomic-embed-text'

DEFAULT_LLM_BASIC_MODEL = 'qwen3:14b'
DEFAULT_LLM_ADVANCED_MODEL = 'qwen3:32b'
LLM_US_LITE_MODEL = 'llama3.2:1b'

heavy_model_lock = asyncio.Lock()
lite_model_sem = asyncio.Semaphore(3)

user_document_states: Dict[str, dict] = {}
background_tasks = set()

IDENTITY_PROMPT = """
You are **PrivAI**, a secure sovereign intelligence powered by local hardware.
1. BEHAVIOR: 
   - Professional, concise, and direct.
   - Do not hallucinate capabilities you do not have.
2. KNOWLEDGE PRIORITY: 
   - [WEB RESEARCH] and [DOCUMENT CONTEXT] are the absolute truth.
   - If the provided context answers the question, use it immediately.
"""

LLAMA_FORCE_PROMPT = """
You are a helpful AI assistant called PrivAI.
You have been provided with Context Information. 
Answer the user's question using ONLY the provided Context. 
"""

SHOPPING_PROMPT = """
You are PrivAI's **Price Hunter**.
1. GOAL: Find the lowest price for the requested item from the provided [WEB RESEARCH].
2. FORMAT: You MUST output a Markdown Table comparing the valid options found.
   | Store | Product Name | Price |
   |-------|--------------|-------|
3. CRITICAL RULES: 
   - **AGGREGATOR RULE**: If the 'Source' is a comparison site (e.g., StaticICE, PCPartPicker), you MUST read the content to find the **actual retailer** name. List the RETAILER in the Store column.
   - If the Source is a direct shop (e.g., Amazon, Newegg), use that name.
   - IGNORE "Monthly Payments" or "Installment" prices. Look for the TOTAL price.
   - If a price seems unrealistic (e.g. $400 for a $2000 GPU), assume it is an error or accessory and ignore it.
4. CONCLUSION: State the best deal clearly.
"""

DEEP_RESEARCH_PROMPT = """
You are PrivAI's **Deep Research Core**.
1. GOAL: Provide a comprehensive, fact-based answer using the [WEB RESEARCH] provided.
2. METHOD:
   - Synthesize data from multiple sources.
   - If sources conflict, note the discrepancy.
   - Prioritize recent data (check dates if available).
3. FORMAT:
   - Use clear Markdown headings.
   - Use bullet points for key facts.
4. CITATIONS: When mentioning a specific fact, briefly reference the Source Name.
"""

for folder in [KB_FOLDER]:
    if not os.path.exists(folder): os.makedirs(folder)

_key_hash = hashlib.sha256(WORKER_SECRET_KEY.encode()).digest()
cipher_suite = Fernet(base64.urlsafe_b64encode(_key_hash))

def log_message(msg):
    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {msg}")

async def send_message(websocket, message_dict: dict):
    try:
        if websocket:
            await websocket.send(json.dumps(message_dict))
            await asyncio.sleep(0)
    except: pass

async def extract_relevant_info(text, question, is_shopping=False, model_to_use=DEFAULT_LLM_BASIC_MODEL):
    if not text or len(text) < 200: return ""
    try:
        if is_shopping:
            sys_msg = f"Data Refiner: Extract info relevant to: '{question}'. IF SHOPPING: List ALL purchasing options found. Extract the **Actual Retailer Name**, Product Name, and TOTAL Price. Output 'NONE' if no prices found."
        else:
            sys_msg = f"Data Refiner: Extract ALL information relevant to: '{question}'. Capture specific dates, statistics, quotes, and technical details. Do not summarize too heavily. Output 'NONE' if irrelevant."

        resp = await client.chat.completions.create(
            model=model_to_use, 
            messages=[{"role":"system","content":sys_msg},{"role":"user","content":text}], 
            temperature=0.0
        )
        content = resp.choices[0].message.content.strip()
        return "" if "NONE" in content.upper() else content
    except: return text[:500]

async def generate_optimized_query(user_question):
    if user_question.lower().strip() in ["hello", "hi", "hey", "yo", "hi there"]: return "SKIP_SEARCH"
    try:
        sys_msg = """You are a Keyword Generator Tool.
        Task: Convert user input into a Google Search string.
        Logic:
        - If shopping, append "price" or "buy online".
        - If research, append "analysis", "wiki", or "news" as appropriate.
        Rules:
        1. Output ONLY the search query.
        2. Do NOT answer the question.
        3. Do NOT refuse.
        """
        resp = await client.chat.completions.create(model=DEFAULT_LLM_BASIC_MODEL, messages=[{"role":"system","content":sys_msg},{"role":"user","content":user_question}], temperature=0.0)
        query = resp.choices[0].message.content.strip().replace('"', '').replace("'", "").replace('`', '').strip()
        if len(query) > 150 or "cannot" in query.lower(): return user_question
        return query
    except: return user_question

def _scrape_sync(url, max_chars=3500):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0'}
        resp = requests.get(url, headers=headers, timeout=4.0) 
        soup = BeautifulSoup(resp.content, 'html.parser')
        
        for tag in soup(['script', 'style', 'nav', 'footer', 'header', 'aside', 'form', 'iframe', 'noscript']):
            tag.decompose()
            
        text = ' '.join(soup.get_text().split())
        return text[:max_chars] 
    except: return ""

async def scrape_full_site(url, max_chars=3500):
    return await asyncio.get_running_loop().run_in_executor(None, _scrape_sync, url, max_chars)

async def search_serper(query):
    if query == "SKIP_SEARCH": return None
    if not SERPER_API_KEY: return None 
    
    url = "https://google.serper.dev/search"
    payload = json.dumps({"q": query, "gl": "us", "hl": "en", "num": 20, "autocorrect": True})
    headers = {'X-API-KEY': SERPER_API_KEY, 'Content-Type': 'application/json'}
    try:
        res = await asyncio.get_running_loop().run_in_executor(None, lambda: requests.post(url, headers=headers, data=payload, timeout=8).json())
        
        search_data = {"ai_overview": "", "results": []}
        if "answerBox" in res: 
            search_data["ai_overview"] = res["answerBox"].get("snippet") or res["answerBox"].get("answer", "")
        elif "knowledgeGraph" in res:
             search_data["ai_overview"] = res["knowledgeGraph"].get("description", "")
        
        if "shopping" in res:
            for item in res.get("shopping", [])[:6]:
                store_name = item.get("source")
                if not store_name and item.get("link"):
                     try: store_name = urlparse(item.get("link")).netloc.replace("www.", "")
                     except: store_name = "Online Store"

                search_data["results"].append({
                    "title": f"[SHOPPING] {item.get('title')} - {item.get('price')}", 
                    "href": item.get("link"),
                    "source": store_name
                })
        
        for item in res.get("organic", []): 
            domain = ""
            if item.get("link"):
                try: domain = urlparse(item.get("link")).netloc.replace("www.", "")
                except: pass
            
            search_data["results"].append({
                "title": item.get("title"), 
                "href": item.get("link"),
                "source": domain
            })
        return search_data
    except Exception as e: 
        log_message(f"Serper API Error: {e}")
        return None

async def chat_logic(question, history, uid, ws, web=False, model="basic", img=None, target="aichat"):
    try:
        selected_model = DEFAULT_LLM_BASIC_MODEL 
        display_name = "PrivAI Basic"
        is_lite_mode = False
        is_turbo_research = False 

        if model == "advanced":
            selected_model = DEFAULT_LLM_ADVANCED_MODEL
            display_name = "PrivAI Advanced"
        elif model == "deep":
            selected_model = DEFAULT_LLM_ADVANCED_MODEL 
            display_name = "PrivAI DeepThink"
        elif model == "usa":
            selected_model = LLM_US_LITE_MODEL
            display_name = "PrivAI US Basic"
            is_lite_mode = True
            is_turbo_research = True
        elif model == "basic":
            selected_model = DEFAULT_LLM_BASIC_MODEL
            display_name = "PrivAI Basic"
            is_turbo_research = True
            
        log_message(f"Task: {uid} | Web: {web} | Model: {display_name} | Target: {target}")
        
        context_ai, context_web = "", ""

        shopping_keywords = ["price", "cost", "buy", "cheapest", "deal", "sale", "purchase", "how much", "rtx", "gpu"]
        is_shopping = any(k in question.lower() for k in shopping_keywords)

        research_lock = lite_model_sem if is_turbo_research else heavy_model_lock
        
        if target == "pdfchat" and uid in user_document_states:
             async with heavy_model_lock:
                state = user_document_states[uid]
                if "chunk_embeddings" in state and len(state["chunk_embeddings"]) > 0:
                    q_emb = await client.embeddings.create(input=[question], model=embedding_model_name)
                    q_vec = q_emb.data[0].embedding
                    sims = cosine_similarity([q_vec], state["chunk_embeddings"])[0]
                    top_indices = np.argsort(sims)[-3:][::-1].tolist()
                    if 0 not in top_indices: top_indices.insert(0, 0)
                    pdf_context = "\n".join([state["text_chunks"][i] for i in top_indices])
                    context_ai += f"### [DOCUMENT CONTEXT]\n{pdf_context}\n\n"

        if img:
            ocr_text = await asyncio.get_running_loop().run_in_executor(None, lambda: pytesseract.image_to_string(Image.open(io.BytesIO(base64.b64decode(img)))))
            context_web += f"IMAGE OCR DATA:\n{ocr_text}\n\n"

        is_greeting = question.lower().strip() in ["hello", "hi", "hey", "yo"]
        if web and not is_greeting:
            
            is_busy = False
            if isinstance(research_lock, asyncio.Lock) and research_lock.locked(): is_busy = True
            elif isinstance(research_lock, asyncio.Semaphore) and research_lock._value == 0: is_busy = True
            
            if is_busy:
                lane_name = "Turbo Lane" if is_turbo_research else "Deep Research"
                await send_message(ws, {"type": "status", "user_id": uid, "data": f"High Traffic: {lane_name} in queue...", "target": target})

            async with research_lock:
                await send_message(ws, {"type": "status", "user_id": uid, "data": "Searching...", "target": target})
                
                opt_q = await generate_optimized_query(question) 
                
                scrape_limit = 12 if model == "deep" else 4

                data = await search_serper(opt_q)
                
                if data:
                    if data["ai_overview"]:
                        context_ai = f"### [PRIMARY SOURCE: GOOGLE AI]\n{data['ai_overview']}\n\n" + context_ai
                    if data["results"]:
                        
                        if is_turbo_research:
                            extraction_model = LLM_US_LITE_MODEL
                            extraction_sem = asyncio.Semaphore(5)
                            char_limit = 4500 
                            await send_message(ws, {"type": "status", "user_id": uid, "data": f"Turbo Scanning {scrape_limit} sources...", "target": target})
                        else:
                            extraction_model = DEFAULT_LLM_BASIC_MODEL
                            extraction_sem = asyncio.Semaphore(1)
                            char_limit = 25000 
                            await send_message(ws, {"type": "status", "user_id": uid, "data": f"Deep Scanning {scrape_limit} sources...", "target": target})
                        
                        sem_download = asyncio.Semaphore(20) 
                        
                        async def fetch_site(r):
                            async with sem_download:
                                try:
                                    source_name = r.get('source', 'Unknown Site')
                                    if "[SHOPPING]" in r['title']:
                                        return { "type": "shopping", "content": f"STORE: {source_name}\nPRODUCT: {r['title']}\nLINK: {r['href']}" }
                                    
                                    txt = await scrape_full_site(r['href'], max_chars=char_limit)
                                    if not txt: return None
                                    return { "type": "site", "title": r['title'], "source": source_name, "content": txt, "href": r['href'] }
                                except: return None
                        
                        tasks = [fetch_site(r) for r in data["results"][:scrape_limit]]
                        raw_results = await asyncio.gather(*tasks)
                        
                        async def process_content_async(res):
                            async with extraction_sem:
                                if not res: return None
                                if res["type"] == "shopping":
                                    return res["content"]
                                else:
                                    relevant = await extract_relevant_info(res["content"], question, is_shopping=is_shopping, model_to_use=extraction_model)
                                    if relevant:
                                        return f"STORE: {res['source']}\nTITLE: {res['title']}\nDATA: {relevant}"
                        
                        extraction_tasks = [process_content_async(r) for r in raw_results]
                        valid_research_raw = await asyncio.gather(*extraction_tasks)
                        valid_research = [x for x in valid_research_raw if x]
                        
                        context_web += "### [WEB RESEARCH]\n\n" + "\n\n".join(valid_research)

        gen_lock = lite_model_sem if is_lite_mode else heavy_model_lock
        gen_lock_name = "Lite Model" if is_lite_mode else "Heavy Model"

        gen_is_busy = False
        if isinstance(gen_lock, asyncio.Lock) and gen_lock.locked(): gen_is_busy = True
        elif isinstance(gen_lock, asyncio.Semaphore) and gen_lock._value == 0: gen_is_busy = True
        
        if gen_is_busy:
            await send_message(ws, {"type": "status", "user_id": uid, "data": f"High Traffic: {gen_lock_name} in queue...", "target": target})

        async with gen_lock:
            await send_message(ws, {"type": "status", "user_id": uid, "data": "Thinking...", "target": target})

            if model == "deep" and not is_greeting:
                thought_resp = await client.chat.completions.create(
                    model=selected_model, 
                    messages=[{"role":"user","content":f"Reason step-by-step: {question}\nContext: {context_ai + context_web}"}], 
                    temperature=0.1
                )
                thought = thought_resp.choices[0].message.content
                context_ai = f"### INTERNAL REASONING:\n{thought}\n\n" + context_ai

            current_system_prompt = IDENTITY_PROMPT
            
            if model == "usa": 
                current_system_prompt = LLAMA_FORCE_PROMPT
            elif is_shopping and model == "deep":
                current_system_prompt = SHOPPING_PROMPT
            elif model == "deep":
                current_system_prompt = DEEP_RESEARCH_PROMPT

            messages = [{"role": "system", "content": current_system_prompt}]
            
            for m in history[-6:]:
                txt = m.get("text") or m.get("content")
                if txt and txt.strip(): messages.append({"role": m.get("role", "user"), "content": str(txt)})
            
            messages.append({"role": "user", "content": f"Context:\n{context_ai + context_web}\n\nQuestion: {question}"})

            try:
                await send_message(ws, {"type": "stream_start", "user_id": uid, "target": target})
                full_res = ""
                
                stream = await client.chat.completions.create(
                    model=selected_model, 
                    messages=messages, 
                    stream=True, 
                    temperature=0.1
                )
                
                async for chunk in stream:
                    token = chunk.choices[0].delta.content or ""
                    
                    full_res += token
                    if token:
                        await send_message(ws, {"type": "stream_chunk", "user_id": uid, "data": token, "target": target})
                
                await send_message(ws, {"type": "stream_end", "user_id": uid, "target": target})
            except asyncio.TimeoutError:
                await send_message(ws, {"type": "error", "user_id": uid, "data": "Neural Timeout.", "target": target})
                return

            if 10 < len(full_res) < 1200:
                comm = edge_tts.Communicate(re.sub(r'[*#`\[\]]', '', full_res), "en-US-AriaNeural")
                with tempfile.NamedTemporaryFile(delete=False, suffix=".mp3") as fp:
                    await comm.save(fp.name)
                    audio_b64 = base64.b64encode(open(fp.name, "rb").read()).decode()
                    await send_message(ws, {"type": "audio_playback", "user_id": uid, "data": audio_b64, "target": target})
                os.remove(fp.name)

    except Exception as e:
        log_message(f"Error: {e}")
        await send_message(ws, {"type": "error", "user_id": uid, "data": "System Error.", "target": target})

async def process_pdf_logic(pdf_b64, user_id, filename, websocket):
    if heavy_model_lock.locked():
         await send_message(websocket, {"type": "status", "user_id": user_id, "data": "Queue: Waiting for processor...", "target": "pdfchat"})

    async with heavy_model_lock:
        try:
            log_message(f"Indexing PDF: {filename}")
            def _task():
                doc = fitz.open(stream=base64.b64decode(pdf_b64), filetype="pdf")
                text = "".join([p.get_text() for p in doc])
                chunks = [text[i:i + 1000] for i in range(0, len(text), 900)]
                sync_client = OpenAI(base_url='http://localhost:11434/v1', api_key='ollama')
                embeddings = [sync_client.embeddings.create(input=[c], model=embedding_model_name).data[0].embedding for c in chunks]
                return {"chunks": chunks, "vectors": np.array(embeddings).astype(np.float32)}
                
            data = await asyncio.get_running_loop().run_in_executor(None, _task)
            user_document_states[user_id] = {"text_chunks": data["chunks"], "chunk_embeddings": data["vectors"]}
            await send_message(websocket, {"type": "upload_complete", "user_id": user_id, "doc_id": "temp", "target": "pdfchat"})
        except Exception as e:
             log_message(f"PDF Error: {e.args}")

async def main():
    global heavy_model_lock, lite_model_sem
    while True:
        try:
            heavy_model_lock = asyncio.Lock()
            lite_model_sem = asyncio.Semaphore(3)
            
            async with websockets.connect(RENDER_SERVER_URL, max_size=2**28, ping_interval=30, ping_timeout=600) as ws:
                await ws.send(json.dumps({"type": "auth", "secret": WORKER_SECRET_KEY}))
                log_message("PrivAI Worker Live.")
                
                async for msg_str in ws:
                    msg = json.loads(msg_str)
                    uid, typ = msg.get("user_id"), msg.get("type")
                    target = msg.get("target", "aichat")

                    if typ == "upload_start": user_document_states[uid] = {'file_chunks': []}
                    elif typ == "upload_chunk": user_document_states[uid].setdefault('file_chunks', []).append(msg["data"])
                    elif typ == "upload_end":
                        full = "".join(user_document_states[uid]['file_chunks'])
                        asyncio.create_task(process_pdf_logic(full, uid, "document.pdf", ws))
                    elif typ in ["ask", "general_chat", "general_chat_with_image"]:
                        d = msg.get("data", {})
                        
                        task = asyncio.create_task(chat_logic(
                            question=d.get("question"), 
                            history=d.get("history", []), 
                            uid=uid, 
                            ws=ws, 
                            web=d.get("enable_web_search"), 
                            model=d.get("model", "basic"), 
                            img=d.get("image_b64"),
                            target=target 
                        ))
                        background_tasks.add(task)
                        task.add_done_callback(background_tasks.discard)

        except Exception as e:
            log_message(f"Connection lost: {e}. Retrying in 5s...")
            for t in background_tasks: t.cancel()
            background_tasks.clear()
            await asyncio.sleep(5)

if __name__ == "__main__": asyncio.run(main())
