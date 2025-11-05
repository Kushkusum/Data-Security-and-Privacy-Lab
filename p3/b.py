"""
Virus Simulation Tool (safe, educational)

How it works (summary):
- Simulates a network of "hosts" connected by a graph (adjacency list).
- A "malware profile" defines infection_strength, stealth (lower => easier to detect),
  and behavior intensity (how noisy it is).
- Each simulation tick: infected hosts may attempt to infect neighbors based on infection_prob.
- Detection engines:
    - Signature-based: matches a simple signature string in the malware profile.
    - Heuristic/behavioral: flags hosts whose "suspicious_score" exceeds threshold.
    - Statistical anomaly: flags hosts with sudden spike in activity.
- Defenses: quarantine (isolate host), patch (reduce vulnerability), logging and alerts.
- All operations are simulated — no real files or networks used.

Use for learning and experimentation only.
"""

import random
import time
from collections import defaultdict, deque

# ---------------------------
# Simulation settings
# ---------------------------
NUM_HOSTS = 30            # number of hosts in the simulated network
AVG_DEGREE = 3            # average number of neighbors per host
SIM_TICKS = 30            # number of time steps to simulate
INITIAL_INFECTED = 2      # number of initially infected hosts

# Detection thresholds
HEURISTIC_THRESHOLD = 7   # suspicious activity threshold to flag
ANOMALY_FACTOR = 3        # factor by which activity spike counts as anomaly

# Defense parameters
QUARANTINE_ON_DETECT = True   # whether to isolate host on detection
PATCH_EFFECTIVENESS = 0.6     # reduces infection probability by this fraction when patched

# ---------------------------
# Malware profiles (simulated)
# ---------------------------
# Keep these simple and descriptive. No payloads, no commands.
MALWARE_PROFILES = {
    "NoisyWorm": {
        "signature": "NWORM_SIG_v1",   # simple signature for signature-based detection
        "infection_strength": 0.6,     # base probability to infect neighbor
        "stealth": 0.2,                # lower => noisier => easier to detect
        "behavior_intensity": 6        # contributes to suspicious_score per tick
    },
    "StealthMiner": {
        "signature": "SMINER_SIG_x",
        "infection_strength": 0.35,
        "stealth": 0.9,                # high stealth => low immediate heuristic score
        "behavior_intensity": 2
    }
}

# ---------------------------
# Host class
# ---------------------------
class Host:
    def __init__(self, host_id):
        self.id = host_id
        self.neighbors = set()
        self.infected = False
        self.malware = None        # name of malware profile if infected
        self.suspicious_score = 0  # simulated behavioral score
        self.activity_history = deque(maxlen=10)  # keep recent activity levels
        self.quarantined = False
        self.patched = False

    def add_neighbor(self, other):
        self.neighbors.add(other)

    def expose_activity(self):
        # Simulate baseline activity (1-3) + malware behavior if infected
        base = random.randint(1, 3)
        mal = 0
        if self.infected and self.malware:
            profile = MALWARE_PROFILES[self.malware]
            mal = int(profile["behavior_intensity"] * random.uniform(0.8, 1.2))
        activity = base + mal
        self.activity_history.append(activity)
        return activity

# ---------------------------
# Network creation
# ---------------------------
def create_random_network(n, avg_degree):
    hosts = [Host(i) for i in range(n)]
    # Connect hosts randomly to approximate avg_degree (undirected)
    for i in range(n):
        # choose number of edges for node i
        desired = max(1, int(random.gauss(avg_degree, 1)))
        while len(hosts[i].neighbors) < desired:
            j = random.randrange(n)
            if j != i:
                hosts[i].add_neighbor(j)
                hosts[j].add_neighbor(i)
    return hosts

# ---------------------------
# Detection engines
# ---------------------------
def signature_detection(host):
    """Simple signature-based detection: if infected and signature known, flag."""
    if host.infected and host.malware:
        sig = MALWARE_PROFILES[host.malware]["signature"]
        # Suppose our signature DB contains both signatures (for demo).
        signature_db = {"NWORM_SIG_v1", "SMINER_SIG_x"}
        if sig in signature_db:
            return True, f"Signature matched: {sig}"
    return False, None

def heuristic_detection(host):
    """Heuristic detection: use suspicious_score derived from behavior intensity."""
    # compute suspicious_score as average recent activity multiplied by stealth inverse
    avg_activity = sum(host.activity_history) / len(host.activity_history) if host.activity_history else 0
    stealth_factor = 1.0
    if host.infected and host.malware:
        stealth_factor = (1.0 / MALWARE_PROFILES[host.malware]["stealth"])
    host.suspicious_score = avg_activity * stealth_factor
    if host.suspicious_score >= HEURISTIC_THRESHOLD:
        return True, f"Heuristic threshold exceeded: score={host.suspicious_score:.1f}"
    return False, None

def anomaly_detection(host):
    """Statistical anomaly: sudden spike in activity vs recent baseline."""
    if len(host.activity_history) < 3:
        return False, None
    recent = list(host.activity_history)
    baseline = sum(recent[:-1]) / (len(recent) - 1)
    last = recent[-1]
    if baseline > 0 and last >= baseline * ANOMALY_FACTOR:
        return True, f"Anomalous spike: last={last}, baseline={baseline:.1f}"
    return False, None

# ---------------------------
# Simulation loop
# ---------------------------
def run_simulation(profile_name="NoisyWorm", verbose=True):
    # Build network
    hosts = create_random_network(NUM_HOSTS, AVG_DEGREE)
    # Infect initial hosts
    initial = random.sample(range(NUM_HOSTS), INITIAL_INFECTED)
    for idx in initial:
        hosts[idx].infected = True
        hosts[idx].malware = profile_name

    logs = []
    stats = {"total_infected": INITIAL_INFECTED, "detected": 0, "quarantined": 0, "patched": 0}

    for tick in range(1, SIM_TICKS + 1):
        if verbose:
            print(f"\n=== Tick {tick} ===")
        # Phase 1: simulate activity on each host
        for host in hosts:
            if host.quarantined:
                host.activity_history.append(0)  # quarantined: no activity
                continue
            activity = host.expose_activity()
            if verbose:
                print(f"Host {host.id:02d} activity={activity} infected={host.infected} patched={host.patched}")

        # Phase 2: detection
        for host in hosts:
            if host.quarantined:
                continue
            # signature
            sig_hit, sig_msg = signature_detection(host)
            heur_hit, heur_msg = heuristic_detection(host)
            anom_hit, anom_msg = anomaly_detection(host)

            detected = False
            reason = None
            if sig_hit:
                detected = True
                reason = sig_msg
            elif heur_hit:
                detected = True
                reason = heur_msg
            elif anom_hit:
                detected = True
                reason = anom_msg

            if detected:
                stats["detected"] += 1
                logs.append((tick, host.id, "DETECTED", reason))
                if verbose:
                    print(f"ALERT on host {host.id}: {reason}")
                if QUARANTINE_ON_DETECT:
                    host.quarantined = True
                    stats["quarantined"] += 1
                    logs.append((tick, host.id, "QUARANTINED", "Isolated due to detection"))
                    if verbose:
                        print(f"Host {host.id} quarantined.")
                # Also "patch" neighbor vulnerabilities as simple mitigation illustration
                for nb in host.neighbors:
                    n = hosts[nb]
                    if not n.patched and random.random() < 0.3:
                        n.patched = True
                        stats["patched"] += 1
                        logs.append((tick, n.id, "PATCHED", "Applied emergency patch"))
                        if verbose:
                            print(f"Host {n.id} patched (emergency).")

        # Phase 3: propagation attempts (only from infected, not quarantined hosts)
        newly_infected = []
        for host in hosts:
            if host.infected and (not host.quarantined):
                profile = MALWARE_PROFILES[host.malware]
                base_infect = profile["infection_strength"]
                for nb in host.neighbors:
                    n = hosts[nb]
                    if n.infected or n.quarantined:
                        continue
                    # if patched, reduce infection probability
                    infect_prob = base_infect * (1 - PATCH_EFFECTIVENESS if n.patched else 1.0)
                    # small randomness
                    if random.random() < infect_prob:
                        newly_infected.append(n.id)
                        logs.append((tick, n.id, "INFECTED", f"Via host {host.id}"))
                        if verbose:
                            print(f"Host {n.id} got infected by host {host.id} (p={infect_prob:.2f}).")
        # Apply new infections
        for nid in newly_infected:
            hosts[nid].infected = True
            hosts[nid].malware = profile_name
            stats["total_infected"] += 1

        # End of tick summary
        if verbose:
            infected_count = sum(1 for h in hosts if h.infected)
            print(f"End of tick {tick}: infected={infected_count} quarantined={sum(h.quarantined for h in hosts)} patched={sum(h.patched for h in hosts)}")

    # Final summary
    print("\n=== Simulation complete ===")
    print(f"Total hosts: {NUM_HOSTS}")
    print(f"Total infected (ever): {stats['total_infected']}")
    print(f"Detections: {stats['detected']}")
    print(f"Quarantined: {stats['quarantined']}")
    print(f"Patched: {stats['patched']}")
    return hosts, logs, stats

# ---------------------------
# CLI / run
# ---------------------------
if __name__ == "__main__":
    print("Safe Virus Simulation Tool - Educational")
    print("Available malware profiles:", ", ".join(MALWARE_PROFILES.keys()))
    choice = input("Choose a profile (press enter for NoisyWorm): ").strip() or "NoisyWorm"
    if choice not in MALWARE_PROFILES:
        print("Unknown profile; using NoisyWorm")
        choice = "NoisyWorm"
    run_simulation(profile_name=choice, verbose=True)
