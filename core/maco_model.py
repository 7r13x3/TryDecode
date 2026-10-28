from pydantic import BaseModel, Field
from typing import List, Optional

class NetworkConfig(BaseModel):
    host: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = "TCP"

class ExtractorModel(BaseModel):
    family: str = Field(..., description="Name of the RAT family (e.g., XWorm)")
    sha256: Optional[str] = None
    network: List[NetworkConfig] = []
    mutex: Optional[str] = None
    encryption_key: Optional[str] = None
    raw_config: dict = Field(default_factory=dict, description="Any extra extracted data")

    class Config:
        populate_by_name = True
