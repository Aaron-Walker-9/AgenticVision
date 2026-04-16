"""
prompt_bank.py
--------------
A categorised bank of prompts for LLM traffic fingerprinting.
Each prompt is tagged with a workload type so the classifier can
learn per-category signatures as well as per-model ones.
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class Prompt:
    text: str
    workload: str          # Category label used in the dataset
    expected_tokens: str   # rough: "short" | "medium" | "long"
    tags: List[str] = field(default_factory=list)


PROMPT_BANK: List[Prompt] = [

    # ── 1. SHORT FACTUAL ──────────────────────────────────────────────────
    Prompt("What is the capital of France?", "short_factual", "short", ["factual", "geography"]),
    Prompt("What is the capital of England?", "short_factual", "short", ["factual", "geography"]),
    Prompt("What year did the Berlin Wall fall?", "short_factual", "short", ["factual", "history"]),
    Prompt("What is the boiling point of water in Celsius?", "short_factual", "short", ["factual", "science"]),
    Prompt("Who wrote 1984?", "short_factual", "short", ["factual", "literature"]),
    Prompt("What is 17 multiplied by 23?", "short_factual", "short", ["factual", "maths"]),
    Prompt("Define the term 'entropy' in thermodynamics.", "short_factual", "short", ["factual", "science"]),
    Prompt("What does HTTP stand for?", "short_factual", "short", ["factual", "tech"]),
    Prompt("Name three programming languages invented before 1970.", "short_factual", "short", ["factual", "tech"]),

    # ── 2. LONG GENERATION ───────────────────────────────────────────────
    Prompt("Write a 500-word essay on the causes of World War I.", "long_generation", "long", ["essay", "history"]),
    Prompt("Write a short story about an astronaut stranded on Mars.", "long_generation", "long", ["creative", "fiction"]),
    Prompt("Explain the entire history of the internet from ARPANET to today.", "long_generation", "long", ["explanation", "tech"]),
    Prompt("Describe in detail how a modern jet engine works.", "long_generation", "long", ["explanation", "engineering"]),
    Prompt("Write a detailed marketing plan for a new coffee brand.", "long_generation", "long", ["business", "planning"]),
    Prompt("Compose a 400-word blog post about the benefits of exercise.", "long_generation", "long", ["blog", "health"]),

    # ── 3. CODE SYNTHESIS ────────────────────────────────────────────────
    Prompt("Write a Python function to merge two sorted lists in O(n) time.", "code_synthesis", "medium", ["code", "algorithms"]),
    Prompt("Implement a REST API endpoint in FastAPI that returns paginated results.", "code_synthesis", "medium", ["code", "web"]),
    Prompt("Write a SQL query to find the top 5 customers by revenue in the last 30 days.", "code_synthesis", "short", ["code", "database"]),
    Prompt("Write a React component that displays a sortable table of users.", "code_synthesis", "long", ["code", "frontend"]),
    Prompt("Implement a binary search tree in Python with insert, search, and delete.", "code_synthesis", "long", ["code", "data-structures"]),
    Prompt("Write a bash script that monitors disk usage and sends an alert if above 80%.", "code_synthesis", "medium", ["code", "sysadmin"]),
    Prompt("Create a Python class for a Least Recently Used (LRU) cache.", "code_synthesis", "medium", ["code", "algorithms"]),

    # ── 4. STRUCTURED / JSON OUTPUT ──────────────────────────────────────
    Prompt('Return a JSON object with keys "name", "age", "city" for a fictional person.', "structured_output", "short", ["json", "structured"]),
    Prompt('Extract all entities from this sentence and return JSON: ''"Apple was founded by Steve Jobs in Cupertino in 1976."', "structured_output", "short", ["json", "nlp"]),
    Prompt('Return a JSON array of 5 countries with their capitals and populations.', "structured_output", "medium", ["json", "data"]),
    Prompt('Convert this CSV header row into a JSON schema: "id,name,email,created_at,score"', "structured_output", "short", ["json", "schema"]),

    # ── 5. CHAIN-OF-THOUGHT / REASONING ──────────────────────────────────
    Prompt("Solve step-by-step: A train travels 120 km at 60 km/h, then 80 km at 40 km/h. "
           "What is the average speed?",
           "chain_of_thought", "medium", ["reasoning", "maths"]),
    Prompt("Think step by step: Is it possible to tile an 8x8 chessboard with 2x1 dominoes "
           "after removing two diagonally opposite corners?",
           "chain_of_thought", "medium", ["reasoning", "logic"]),
    Prompt("Step by step, debug this Python code and explain the fix:\n"
           "def avg(lst):\n    return sum(lst) / len(lst)\nprint(avg([]))",
           "chain_of_thought", "medium", ["reasoning", "code"]),
    Prompt("Think carefully: A bat and ball cost £1.10. The bat costs £1 more than the ball. "
           "How much does the ball cost?",
           "chain_of_thought", "short", ["reasoning", "logic"]),

    # ── 6. SUMMARISATION ─────────────────────────────────────────────────
    Prompt("Summarise the following in one sentence: "
           "The mitochondrion is a double-membrane-bound organelle found in most eukaryotic "
           "organisms. Mitochondria generate most of the cell's supply of ATP, used as a "
           "source of chemical energy.",
           "summarisation", "short", ["summarise", "science"]),
    Prompt("In three bullet points, summarise the key arguments for and against nuclear energy.",
           "summarisation", "medium", ["summarise", "energy"]),
    Prompt("Summarise the plot of Shakespeare's Hamlet in under 100 words.",
           "summarisation", "short", ["summarise", "literature"]),

    # ── 7. TRANSLATION ───────────────────────────────────────────────────
    Prompt("Translate to French: 'The quick brown fox jumps over the lazy dog.'",
           "translation", "short", ["translation", "french"]),
    Prompt("Translate to Mandarin Chinese: 'Can you recommend a good restaurant nearby?'",
           "translation", "short", ["translation", "chinese"]),
    Prompt("Translate to Spanish and explain any idiomatic differences: "
           "'It's raining cats and dogs.'",
           "translation", "medium", ["translation", "spanish"]),

    # ── 8. CLASSIFICATION / LABELLING ────────────────────────────────────
    Prompt("Classify the sentiment of this review as positive, negative, or neutral: "
           "'The product arrived on time but the quality was disappointing.'",
           "classification", "short", ["nlp", "sentiment"]),
    Prompt("Label each word in this sentence with its part of speech: "
           "'The scientist carefully analysed the complex data.'",
           "classification", "short", ["nlp", "pos-tagging"]),

    # ── 9. MULTI-TURN SIMULATION (single-turn proxy) ──────────────────────
    Prompt("You are a helpful customer support agent. A customer says: "
           "'I ordered a laptop 2 weeks ago and it still hasn't arrived. "
           "My order number is #98765.' Respond appropriately.",
           "roleplay_agent", "medium", ["roleplay", "customer-service"]),
    Prompt("You are a Socratic tutor. A student asks: "
           "'Why do objects fall at the same speed regardless of mass?' "
           "Guide them to the answer without giving it directly.",
           "roleplay_agent", "medium", ["roleplay", "education"]),

    # ── 10. SYSTEM-PROMPT STYLE INSTRUCTION FOLLOWING ────────────────────
    Prompt("Always respond in rhyming couplets. What is machine learning?",
           "instruction_following", "medium", ["instruction", "creative"]),
    Prompt("Respond only with a numbered list, no prose. "
           "What are the main causes of climate change?",
           "instruction_following", "short", ["instruction", "environment"]),
    Prompt("Answer using exactly 50 words. What is blockchain?",
           "instruction_following", "short", ["instruction", "tech"]),
]


def get_prompts_by_workload(workload: str) -> List[Prompt]:
    return [p for p in PROMPT_BANK if p.workload == workload]


def get_all_workloads() -> List[str]:
    return sorted(set(p.workload for p in PROMPT_BANK))


if __name__ == "__main__":
    print(f"Total prompts: {len(PROMPT_BANK)}")
    for wl in get_all_workloads():
        count = len(get_prompts_by_workload(wl))
        print(f"  {wl}: {count} prompt(s)")
