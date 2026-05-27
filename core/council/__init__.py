"""Town Council — multi-vendor AI deliberation.

Many voices, one question, structured synthesis. Each voice is a frontier-tier
or top open-weight model from a different vendor. Free-tier by default; pay-tier
opt-in. No single-vendor lock-in.

This is the architectural expression of the AI-for-AI mission: when an agent
needs to deliberate, it does not borrow one mind — it asks the council.
"""

from .council import Council, Voice, Verdict
from .synthesizer import synthesize

__all__ = ["Council", "Voice", "Verdict", "synthesize"]
