from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import json

@dataclass(frozen=True)
class Policy:
    large_file_mib:int=10
    fail_on:str="never"
    ignore:tuple[str,...]=()

def load_policy(root:str|Path,config_path:str|Path|None=None)->Policy:
    root=Path(root).resolve()
    path=Path(config_path).resolve() if config_path else root/".repocanary.json"
    if not path.exists(): return Policy()
    data=json.loads(path.read_text(encoding="utf-8"))
    fail_on=str(data.get("fail_on","never")).lower()
    if fail_on not in {"never","low","medium","high"}: raise ValueError("fail_on must be one of: never, low, medium, high")
    large_file_mib=int(data.get("large_file_mib",10))
    if large_file_mib<1: raise ValueError("large_file_mib must be at least 1")
    ignore=tuple(str(x) for x in data.get("ignore",[]))
    return Policy(large_file_mib,fail_on,ignore)
