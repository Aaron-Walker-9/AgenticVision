"""
prompt_bank.py
--------------
A categorised bank of prompts for LLM traffic fingerprinting.
Each prompt is tagged with a workload type so the classifier can learn per-category signatures as well as per-model ones.
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


    # ── 2. LONG GENERATION ───────────────────────────────────────────────
    Prompt("Write a 500-word essay on the causes of World War I.", "long_generation", "long", ["essay", "history"]),


    # ── 3. CODE SYNTHESIS ────────────────────────────────────────────────
    Prompt("Write a Python function to merge two sorted lists in O(n) time.", "code_synthesis", "medium", ["code", "algorithms"]),


    # ── 4. STRUCTURED / JSON OUTPUT ──────────────────────────────────────
    Prompt('Return a JSON object with keys "name", "age", "city" for a fictional person.', "structured_output", "short", ["json", "structured"]),


    # ── 5. CHAIN-OF-THOUGHT / REASONING ──────────────────────────────────
    Prompt("Solve step-by-step: A train travels 120 km at 60 km/h, then 80 km at 40 km/h. "
           "What is the average speed?",
           "chain_of_thought", "medium", ["reasoning", "maths"]),


    # ── 6. SUMMARISATION ─────────────────────────────────────────────────
    Prompt("Summarise the following in one sentence: "
           "The mitochondrion is a double-membrane-bound organelle found in most eukaryotic "
           "organisms. Mitochondria generate most of the cell's supply of ATP, used as a "
           "source of chemical energy.",
           "summarisation", "short", ["summarise", "science"]),


    # ── 7. TRANSLATION ───────────────────────────────────────────────────
    Prompt("Translate to French: 'The quick brown fox jumps over the lazy dog.'",
           "translation", "short", ["translation", "french"]),


    # ── 8. CLASSIFICATION / LABELLING ────────────────────────────────────
    Prompt("Classify the sentiment of this review as positive, negative, or neutral: "
           "'The product arrived on time but the quality was disappointing.'",
           "classification", "short", ["nlp", "sentiment"]),


    # ── 9. MULTI-TURN SIMULATION (single-turn proxy) ──────────────────────
    Prompt("You are a helpful customer support agent. A customer says: "
           "'I ordered a laptop 2 weeks ago and it still hasn't arrived. "
           "My order number is #98765.' Respond appropriately.",
           "roleplay_agent", "medium", ["roleplay", "customer-service"]),


    # ── 10. SYSTEM-PROMPT STYLE INSTRUCTION FOLLOWING ────────────────────
    Prompt("Always respond in rhyming couplets. What is machine learning?",
           "instruction_following", "medium", ["instruction", "creative"]),
    
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
