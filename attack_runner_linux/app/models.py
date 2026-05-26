from pydantic import BaseModel
from typing import Optional, Dict, Any

class RunScenarioRequest(BaseModel):
    scenario_id: str
    request_id: Optional[str] = None
    params: Optional[Dict[str, Any]] = None