from typing import List, Dict, Any

def generate_feature_vector(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate a summary of vulnerability counts as feature vector.
    """
    feature_vector = {
        "generally_dangerous_calls": 0,
        "unprotected_critical_calls": 0,
        "tainted_input_in_dangerous_calls": 0,
        "tainted_param_source_calls": 0,
        "dangerous_dynamic_sql": 0,
        "tainted_flows": 0,
        "missing_error_handling": 0,
        "deep_control_nesting": 0,
        "uninitialized_variable_usage": 0,
        "tainted_file_access": 0,
        "unsafe_deserialization": 0,
        "buffer_overflow_risk": 0,
        "toctou_risk": 0
    }

    for vuln in vulnerabilities:
        vtype = vuln.get("type")
        if vtype == "Generally Dangerous Function Call":
            feature_vector["generally_dangerous_calls"] += 1
        elif vtype == "Dangerous Function Call: Critical Sink Needing Try":
            feature_vector["unprotected_critical_calls"] += 1
        elif vtype == "Dangerous Function Call: Tainted Parameter Source":
            feature_vector["tainted_input_in_dangerous_calls"] += 1
        elif vtype == "Dangerous Function Call: Tainted Parameter Source":
            feature_vector["tainted_param_source_calls"] += 1
        elif vtype == "Dangerous Dynamic SQL Query":
            feature_vector["dangerous_dynamic_sql"] += 1
        elif vtype == "Tainted Data Flow to Dangerous Sink":
            feature_vector["tainted_flows"] += 1
        elif vtype == "Missing Error Handling":
            feature_vector["missing_error_handling"] += 1
        elif vtype == "Excessive Control Structure Nesting":
            feature_vector["deep_control_nesting"] += 1
        elif vtype == "Use of Uninitialized Variable":
            feature_vector["uninitialized_variable_usage"] += 1
        elif vtype == "Tainted File Access (open)":
            feature_vector["tainted_file_access"] += 1
        elif vtype == "Unsafe Deserialization":
            feature_vector["unsafe_deserialization"] += 1
        elif vtype == "Copy without length control, Buffer Overflow risk":
            feature_vector["buffer_overflow_risk"] += 1
        elif vtype == "Potential TOCTOU vulnerability":
            feature_vector["toctou_risk"] += 1

    return feature_vector