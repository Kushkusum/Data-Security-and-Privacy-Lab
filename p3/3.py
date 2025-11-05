import random
import tkinter as tk
from tkinter import messagebox, scrolledtext

# -------------------------
# File Object
class File:
    def __init__(self, name):
        self.name = name
        self.infected = False
        self.quarantined = False
        self.quarantine_timer = 0

# -------------------------
# Computer Object
class Computer:
    def __init__(self, name, file_count=6):
        self.name = name
        self.files = [File(f"{name}_file_{i}.txt") for i in range(file_count)]
        self.infected = False

    def infect_file(self, chance=0.3):
        target = random.choice(self.files)
        if not target.infected and not target.quarantined and random.random() < chance:
            target.infected = True
            self.infected = True
            return target.name
        return None

    def spread_within(self, chance=0.2):
        events = []
        for file in self.files:
            if file.infected and not file.quarantined:
                target = random.choice(self.files)
                if not target.infected and random.random() < chance:
                    target.infected = True
                    self.infected = True
                    events.append(f"{target.name} infected internally")
        return events

    def scan_and_quarantine(self, chance=0.3):
        events = []
        for file in self.files:
            if file.infected and not file.quarantined and random.random() < chance:
                file.quarantined = True
                file.quarantine_timer = 2
                events.append(f"{file.name} quarantined")
        return events

    def recover_files(self):
        events = []
        for file in self.files:
            if file.quarantined:
                file.quarantine_timer -= 1
                if file.quarantine_timer <= 0:
                    file.infected = False
                    file.quarantined = False
                    events.append(f"{file.name} recovered")
        self.infected = any(f.infected for f in self.files)
        return events

# -------------------------
# Virus Simulation (grid-based only)
class VirusSimulation:
    def __init__(self, gui, computers=6, files=6, infection_chance=0.4, detection_chance=0.3):
        self.gui = gui
        self.computers = [Computer(f"PC_{i}", files) for i in range(computers)]
        self.infection_chance = infection_chance
        self.detection_chance = detection_chance

    def infect_random_computer(self, initial_infections=1):
        events = []
        for _ in range(initial_infections):
            comp_idx = random.randrange(len(self.computers))
            name = self.computers[comp_idx].infect_file(chance=1.0)
            events.append(f"{self.computers[comp_idx].name} initial infection -> {name}")
        return events

    def step_cycle(self):
        events = []
        for comp in self.computers:
            events += comp.spread_within()
        for i, comp in enumerate(self.computers):
            if comp.infected:
                target = random.choice([c for c in self.computers if c != comp])
                fname = target.infect_file(self.infection_chance)
                if fname:
                    events.append(f"{target.name}: {fname} infected from {comp.name}")
        for comp in self.computers:
            events += comp.scan_and_quarantine(self.detection_chance)
        for comp in self.computers:
            events += comp.recover_files()
        return events

    def get_totals(self):
        total_files = sum(len(c.files) for c in self.computers)
        infected = sum(f.infected for c in self.computers for f in c.files)
        quarantined = sum(f.quarantined for c in self.computers for f in c.files)
        return total_files, infected, quarantined

# -------------------------
# GUI Class (grid only)
class VirusSimulationGUI:
    
    def __init__(self, root):
        self.root = root
        self.root.title("💻 Virus Simulation Tool — Grid View")
        self.root.geometry("1200x700")
        self.root.configure(bg="#0f1724")
        self.cycle_stats = []  # track per-cycle stats

        # Controls
        control_frame = tk.Frame(root, bg="#091025", padx=12, pady=12)
        control_frame.pack(side='left', fill='y')

        tk.Label(control_frame, text="Controls", bg="#091025", fg="#ffffff", font=("Segoe UI", 12, "bold")).pack(pady=6)

        self.entry_computers = self._add_input(control_frame, "Computers", "6")
        self.entry_files = self._add_input(control_frame, "Files/Computer", "6")
        self.entry_infect = self._add_input(control_frame, "Infection Chance (0-1)", "0.4")
        self.entry_detect = self._add_input(control_frame, "Detection Chance (0-1)", "0.3")
        self.entry_cycles = self._add_input(control_frame, "Cycles", "12")
        self.entry_delay = self._add_input(control_frame, "Delay (ms)", "800")

        btn_frame = tk.Frame(control_frame, bg="#091025")
        btn_frame.pack(pady=10)
        self.btn_start = tk.Button(btn_frame, text="Start", command=self.start_simulation, bg="#10b981", fg="#021018",
                                   width=10, font=("Segoe UI", 12, "bold"))
        self.btn_start.grid(row=0, column=0, padx=6)
        self.btn_stop = tk.Button(btn_frame, text="Stop", command=self.stop_simulation, bg="#ef4444", fg="#fff",
                                  width=10, font=("Segoe UI", 12, "bold"), state='disabled')
        self.btn_stop.grid(row=0, column=1, padx=6)

        reset_btn = tk.Button(control_frame, text="Reset Log", command=self.reset_log, bg="#374151", fg="#fff", font=("Segoe UI", 11))
        reset_btn.pack(pady=6)

        # Main display
        self.grid_frame = tk.Frame(root, bg="#071020")
        self.grid_frame.pack(side='left', fill='both', expand=True, padx=8, pady=8)

        bottom = tk.Frame(root, bg="#06101a", height=180)
        bottom.pack(fill='x')
        stats_l = tk.Frame(bottom, bg="#06101a")
        stats_l.pack(side='left', fill='y', padx=8, pady=8)
        tk.Label(stats_l, text="Stats", bg="#06101a", fg="#bfe9ff", font=("Segoe UI", 11, "bold")).pack(anchor='nw')
        self.stats_text = tk.Label(stats_l, text="Ready", bg="#06101a", fg="#e6f7ff", justify='left')
        self.stats_text.pack(anchor='nw')

        log_frame = tk.Frame(bottom, bg="#000")
        log_frame.pack(side='right', fill='both', expand=True, padx=8, pady=8)
        tk.Label(log_frame, text="Event Log", bg="#000", fg="#8cffc9", font=("Consolas", 10, "bold")).pack(anchor='nw')
        self.log_box = scrolledtext.ScrolledText(
            log_frame,
            height=20,             # more lines visible
            width=80,              # wider display
            bg="#020202",
            fg="#b7f5d6",
            font=("Consolas", 10),
            wrap=tk.WORD            # wraps long lines instead of horizontal scroll
        )
        self.log_box.pack(fill='both', expand=True)

        # Internal simulation state
        self.simulation = None
        self.current_cycle = 0
        self.total_cycles = 0
        self.running = False
        self.delay_ms = 800

    def _add_input(self, frame, label, default):
        tk.Label(frame, text=label, bg="#091025", fg="#cfe7ff").pack(pady=2, anchor='w')
        entry = tk.Entry(frame, width=12)
        entry.insert(0, default)
        entry.pack(pady=2)
        return entry

    def reset_log(self):
        self.log_box.delete('1.0', tk.END)

    def start_simulation(self):
        try:
            computers = int(self.entry_computers.get())
            files = int(self.entry_files.get())
            infect = float(self.entry_infect.get())
            detect = float(self.entry_detect.get())
            cycles = int(self.entry_cycles.get())
            delay = int(self.entry_delay.get())
        except ValueError:
            messagebox.showerror("Input error", "Please enter valid numeric values")
            return

        self.simulation = VirusSimulation(self, computers, files, infect, detect)
        inits = self.simulation.infect_random_computer(initial_infections=max(1, computers//4))
        for e in inits:
            self.log(e)

        self.current_cycle = 0
        self.total_cycles = cycles
        self.delay_ms = delay
        self.running = True
        self.btn_start.config(state='disabled')
        self.btn_stop.config(state='normal')
        self.cycle_stats = []  # reset stats for new simulation

        self.update_grid()
        self.root.after(400, self.run_cycle)

    def stop_simulation(self):
        self.running = False
        self.btn_start.config(state='normal')
        self.btn_stop.config(state='disabled')
        self.log('[STOP] Simulation halted')

    def run_cycle(self):
        if not self.running:
            return

        if self.current_cycle >= self.total_cycles:
            self.running = False
            self.btn_start.config(state='normal')
            self.btn_stop.config(state='disabled')
            self.log(f'[END] Completed {self.total_cycles} cycles')

            # --- Final cumulative summary ---
            self.log("\n=== FINAL CUMULATIVE SUMMARY ===")
            for i, (inf, quar) in enumerate(self.cycle_stats, start=1):
                self.log(f"Cycle {i}: Infected = {inf}, Quarantined = {quar}")
            return

        self.current_cycle += 1
        events = self.simulation.step_cycle()
        self.update_grid()

        # Track per-cycle stats
        total_files, infected, quarantined = self.simulation.get_totals()
        self.cycle_stats.append((infected, quarantined))

        self.log(f'[CYCLE {self.current_cycle}] {len(events)} events')
        for ev in events:
            self.log(f'  - {ev}')
        self.root.after(self.delay_ms, self.run_cycle)

    def update_grid(self):
        # Update stats
        total_files, infected, quarantined = self.simulation.get_totals()
        self.stats_text.config(text=f"Cycles: {self.current_cycle}/{self.total_cycles}\n"
                                    f"Files: {total_files}\n"
                                    f"Infected: {infected}\n"
                                    f"Quarantined: {quarantined}")

        # Clear grid
        for widget in self.grid_frame.winfo_children():
            widget.destroy()

        # Draw grid
        cols = 4
        for idx, comp in enumerate(self.simulation.computers):
            cf = tk.LabelFrame(self.grid_frame, text=comp.name, bg='#0b1220', fg='#cfe7ff', font=("Segoe UI", 10, "bold"))
            cf.grid(row=idx//cols, column=idx%cols, padx=8, pady=8)
            for f in comp.files:
                color = '#32CD32' if not f.infected and not f.quarantined else ('#FFD700' if f.quarantined else '#FF6347')
                tk.Label(cf, text=f.name, bg=color, width=20, anchor='w', font=("Segoe UI", 9)).pack(anchor='w', pady=1)

    def log(self, msg):
        self.log_box.insert(tk.END, msg + "\n")
        self.log_box.see(tk.END)

# -------------------------
if __name__ == '__main__':
    root = tk.Tk()
    app = VirusSimulationGUI(root)
    root.mainloop()
