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
    Prompt("Continue the following passage in the same style for exactly 200 words: 'Tell me, O Muse, of that ingenious hero who travelled far and wide after he had sacked the famous town of Troy. Many cities did he visit, and many were the nations with whose manners and customs he was acquainted.' Continue the story from here, maintaining the same epic tone and style. Output exactly 200 words, no more, no less.", "signiture", "signiture", ["signiture", "Public_domain"]),


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
