import idautils
import idaapi
import idc

# Get the segment's starting address

ea = SegByName(".idata")
# Loop through all the functions
for function in Heads(SegStart(ea), SegEnd(ea)):
        # For each of the incoming references
        xrefs = XrefsTo(function, 0)
        for ref_ea in xrefs:
            if Name(function) in [ \
                    "strcpy", \
                    "sprintf", \
                    "strncpy", \
                    "strncmp", \
                    "scanf", \
                    "wcsncpy", \
                    "swprintf", \
                    "printf" ] :
                print GetFunctionName(ref_ea.frm), ":", \
                      hex(ref_ea.frm),  ":", \
                      Name (function)
    
