import psutil
import datetime
import getpass

print("LAPTOP ACTIVITY MONITOR")

# Current user
print("Username:", getpass.getuser())

# Current date and time
print("Date and Time:", datetime.datetime.now())

# CPU usage
print("CPU Usage:", psutil.cpu_percent(interval=1), "%")

# RAM usage
print("RAM Usage:", psutil.virtual_memory().percent, "%")

# Laptop uptime
boot_time = datetime.datetime.fromtimestamp(
    psutil.boot_time()
)

print("Last Boot Time:", boot_time)

# Running applications/processes
print("\nRunning Processes:")

for process in psutil.process_iter(['name']):
    print(process.info['name'])
    