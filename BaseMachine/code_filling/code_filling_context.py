from pydantic import BaseModel, Field
from typing import List

# Context data model
class CFContext(BaseModel):
    name: str = Field(description="Function or Class name")
    context_code: str = Field(description="The callsite code of the function")

# class Definition(BaseModel):


