import keyboard  # pip install keyboard

# Initialize counter
count = 0

print("Press the SPACE bar to increment the counter. Press ESC to exit.")

# Define a function to increment the counter
def increment_counter(event):
    global count
    count += 1
    print(f"Counter: {count}")

# Bind the space bar to the function
keyboard.on_press_key("space", increment_counter)

# Keep the program running until ESC is pressed
keyboard.wait("esc")
print("Exiting program.")
