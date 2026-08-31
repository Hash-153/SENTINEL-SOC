"""Zero-Trust Policy-as-Code Compiler and Grammar Validator."""
from typing import Dict, List, Any

class PolicyCompiler:
    """Compiles high-level YAML/JSON Zero-Trust policies into executable evaluation trees."""
    @staticmethod
    def compile_rule_dsl(dsl_dict: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "compiled": True,
            "rule_id": dsl_dict.get("id", "UNKNOWN"),
            "allow_roles": dsl_dict.get("roles", []),
            "required_mfa": dsl_dict.get("mfa", True),
        }
