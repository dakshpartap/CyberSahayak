# modules/chatbot/knowledge_base/ingest.py
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS
import os

def build_knowledge_base(docs_folder: str = "modules/chatbot/knowledge_base/"):
    """
    Reads all .txt files in the knowledge_base folder,
    splits them into chunks, embeds them, and saves a FAISS index.
    """
    # Load documents
    documents = []
    for filename in os.listdir(docs_folder):
        if filename.endswith('.txt'):
            with open(os.path.join(docs_folder, filename), 'r', encoding='utf-8') as f:
                documents.append({'content': f.read(), 'source': filename})
    
    # Split into chunks
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=500,
        chunk_overlap=50,
        separators=["\n\n", "\n", ". ", " "]
    )
    chunks = []
    for doc in documents:
        for chunk in splitter.split_text(doc['content']):
            chunks.append(chunk)
    
    # Embed using a free local model (no API key needed)
    embedder = HuggingFaceEmbeddings(
        model_name="sentence-transformers/all-MiniLM-L6-v2"
        # 22MB model, runs on CPU, good for cybersecurity text
    )
    
    # Build and save FAISS index
    db = FAISS.from_texts(chunks, embedder)
    db.save_local("modules/chatbot/knowledge_base/faiss_index")
    print(f"Knowledge base built with {len(chunks)} chunks.")
    return db