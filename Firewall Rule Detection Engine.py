
#==============================
#Firewall Rule Detection Engine
#==============================


#Event Data

events = [
    ("malware", "trusted"),
    ("normal_activity", "trusted"),
    ("failed_login", "trusted"),
    ("normal_activity", "unknown")
]


# Rule Functions


def rule_block(event, device):
    if event == "malware":
        return "BLOCK"

def rule_investigate(event, device):
    if event == "failed_login":
        return "INVESTIGATE"

def rule_allow(event, device):
    if device == "trusted":
        return "ALLOW"



# Rule Engine Setup


rules = [
    rule_block,
    rule_investigate,
    rule_allow
]



# Decision Engine 


def decide_action(event, device):
    results = []

    for rule in rules:
        result = rule(event, device)
        if result:
            results.append(result)

    # priority resolution 
    if "BLOCK" in results:
        return "BLOCK"
    elif "INVESTIGATE" in results:
        return "INVESTIGATE"
    elif "ALLOW" in results:
        return "ALLOW"
    else:
        return "UNKNOWN"



# Process Engine


block_count = 0
investigate_count = 0
allow_count = 0
unknown_count = 0


#Loop through events and make decisions.

for event, device in events:
    action = decide_action(event, device)

    if action == "BLOCK":
        block_count += 1
    elif action == "INVESTIGATE":
        investigate_count += 1
    elif action == "ALLOW":
        allow_count += 1
    else:
        unknown_count += 1

    print("Event:", event, "| Device:", device, "| Action:", action)



# Summary


print("\n--- SUMMARY ---")
print("BLOCK:", block_count)
print("INVESTIGATE:", investigate_count)
print("ALLOW:", allow_count)
print("UNKNOWN:", unknown_count)

    
