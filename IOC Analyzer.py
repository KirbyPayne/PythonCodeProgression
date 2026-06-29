



#=====================

#IOC ANAYLZER

#======================


#Observed IPs Dataset

observed_ips = [
    "10.10.10.5",
    "8.8.8.8",
    "185.220.101.5",
    "192.168.1.1"
]


#Malicious IPs Dataset


malicious_ips = [
    "10.10.10.5",
    "185.220.101.5"
]

#Severity Level Dataset

severity_level = {
    "10.10.10.5": "Medium Risk",
    "185.220.101.5": "High Risk"
}


#Counter For Malicious IPs

malicious_count =0


#Loop Through Observed IPs

for ip in observed_ips:
    if ip in malicious_ips:
        malicious_count += 1
        print("Checking",ip,"...")
        print("Malicious IP detected!", severity_level)
    else:
        print("Checking",ip, "...")
        print("Clean")

print("Scan complete")
print("Malicious IPs found:", malicious_count)










