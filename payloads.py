import uuid
import random
import html

class PayloadGenerator:
    def __init__(self, marker_prefix="PX", randomize=True):
        self.marker_prefix = marker_prefix
        self.randomize = randomize

    def _marker(self):
        uid = uuid.uuid4().hex[:6]
        if self.randomize:
            return f"{self.marker_prefix}{uid}"
        else:
            return f"{self.marker_prefix}000000"

    def for_context(self, context):
        ctx = context.lower()
        marker = self._marker()
        payloads = []

        if ctx == "tag_name":
            payloads = [
                f"<{marker}>",             
                f"{marker}bad",            
                f"{marker} onmouseover=1" 
            ]

        elif ctx == "attr_name":
            payloads = [
                f"{marker}='1'",                 
                f"{marker}=",                   
                f"onmouseover{marker}=1",        
                f" {marker} data='{marker}'"     
            ]

        elif ctx == "attr_value":
            payloads = [
                f"\"{marker}\"",                 
                f"'{marker}'",                   
                f"{marker}",                     
                f"\"{marker}' onmouseover=1 //\"" 
            ]

        elif ctx == "text":
            payloads = [
                f"{marker}",
                f"<script>console.log('{marker}')</script>",
                f"»{marker}«"  
            ]

        elif ctx == "js":
            payloads = [
                f"'{marker}'",
                f'"{marker}"',
                f"/*{marker}*/",
                f"{marker};"  
            ]

        else:
            payloads = [marker]
        unique = []
        for p in payloads:
            if p not in unique:
                unique.append(p)
        return unique

    def choose_for_positions(self, positions):
        return {pos: self.for_context(pos)[0] for pos in positions}
