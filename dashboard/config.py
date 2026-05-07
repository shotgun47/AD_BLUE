import os

BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000")
ATTACK_REQUESTED_BY = os.getenv("ATTACK_REQUESTED_BY", "")
VICTIM_URL = os.getenv("VICTIM_URL", "")

SCENARIO_TYPE_STYLE_MAP = {
    "real_attack": {
        "bg": "#fee2e2",
        "fg": "#991b1b",
        "label": "real_attack",
    },
    "detection_test": {
        "bg": "#fef3c7",
        "fg": "#92400e",
        "label": "detection_test",
    },
    "tools": {
        "bg": "#ecfeff",
        "fg": "#155e75",
        "label": "tools",
    },
    "general": {
        "bg": "#e0f2fe",
        "fg": "#075985",
        "label": "general",
    },
}