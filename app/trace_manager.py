"""
Trace Manager - Trace ID generation and linking logic
Handles trace ID generation and trace data management for linking
Pipeline view → Surface view → Approval modal → Audit log → Evidence export
"""

import uuid
from datetime import datetime
from typing import Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class TraceData:
    """Complete trace data for a request"""
    trace_id: str
    timestamp: str
    request_data: Dict[str, Any]
    pipeline_results: Dict[str, Any]  # Gate results
    surface_activations: Dict[str, Any]  # Which surfaces were touched
    approvals: list = field(default_factory=list)
    audit_entries: list = field(default_factory=list)
    verdict: str = None
    resolution: Optional[str] = None


class TraceManager:
    """Manages trace ID generation and trace data storage"""
    
    def __init__(self):
        self.traces: Dict[str, TraceData] = {}
    
    def generate_trace_id(self) -> str:
        """Generate a unique trace ID"""
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        unique_id = str(uuid.uuid4())[:8].upper()
        return f"TRACE-{timestamp}-{unique_id}"
    
    def create_trace(
        self,
        request_data: Dict[str, Any],
        pipeline_results: Dict[str, Any],
        surface_activations: Dict[str, Any] = None
    ) -> TraceData:
        """Create a new trace and store it"""
        trace_id = self.generate_trace_id()
        trace = TraceData(
            trace_id=trace_id,
            timestamp=datetime.utcnow().isoformat() + "Z",
            request_data=request_data,
            pipeline_results=pipeline_results,
            surface_activations=surface_activations or {},
            verdict=pipeline_results.get("final_verdict"),
            resolution=None
        )
        self.traces[trace_id] = trace
        return trace
    
    def get_trace(self, trace_id: str) -> Optional[TraceData]:
        """Retrieve trace data by ID"""
        return self.traces.get(trace_id)
    
    def update_trace(self, trace_id: str, **updates):
        """Update trace data"""
        if trace_id in self.traces:
            trace = self.traces[trace_id]
            for key, value in updates.items():
                if hasattr(trace, key):
                    setattr(trace, key, value)
    
    def add_approval_to_trace(self, trace_id: str, approval_data: Dict[str, Any]):
        """Add approval record to trace"""
        if trace_id in self.traces:
            self.traces[trace_id].approvals.append(approval_data)
            # Update resolution if approval was processed
            if "status" in approval_data:
                self.traces[trace_id].resolution = approval_data["status"]
    
    def add_audit_to_trace(self, trace_id: str, audit_entry: Dict[str, Any]):
        """Add audit entry to trace"""
        if trace_id in self.traces:
            self.traces[trace_id].audit_entries.append(audit_entry)
    
    def get_all_traces(self) -> list:
        """Get all traces as dictionaries"""
        return [self.to_dict(trace) for trace in self.traces.values()]
    
    def to_dict(self, trace: TraceData) -> Dict[str, Any]:
        """Convert trace to dictionary safely, avoiding recursion issues"""
        # Manual conversion to avoid recursion with deeply nested structures
        return {
            "trace_id": trace.trace_id,
            "timestamp": trace.timestamp,
            "request_data": trace.request_data,
            "pipeline_results": trace.pipeline_results,
            "surface_activations": trace.surface_activations,
            "approvals": trace.approvals,
            "audit_entries": trace.audit_entries,
            "verdict": trace.verdict,
            "resolution": trace.resolution
        }

