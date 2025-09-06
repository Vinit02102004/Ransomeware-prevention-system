from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime
from typing import List, Optional
from bson import ObjectId

class PyObjectId(str):
    @classmethod
    def __get_pydantic_core_schema__(cls, _source_type, _handler):
        import pydantic_core
        return pydantic_core.core_schema.json_or_python_schema(
            json_schema=pydantic_core.core_schema.str_schema(),
            python_schema=pydantic_core.core_schema.is_instance_schema(ObjectId),
            serialization=pydantic_core.core_schema.plain_serializer_function_ser_schema(
                lambda x: str(x)
            ),
        )

class Threat(BaseModel):
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    type: str
    ip: str
    timestamp: datetime

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str},
        populate_by_name=True
    )

class SecurityEvent(BaseModel):
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    event: str
    source: str
    timestamp: datetime
    severity: str

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str},
        populate_by_name=True
    )

class SystemStatus(BaseModel):
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    status: str
    protection_level: str
    scan_count: int

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str},
        populate_by_name=True
    )

class SecurityAnalytics(BaseModel):
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    total_threats: int
    threat_activity: int
    response_time: str
    backed_threats: int

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str},
        populate_by_name=True
    )

class HoneyFile(BaseModel):
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    name: str
    timestamp: datetime

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str},
        populate_by_name=True
    )

class ProtectionLevelUpdate(BaseModel):
    level: str

class EmergencyAction(BaseModel):
    action: str