import tkinter as tk
from socket_helper import SocketError, SocketServer

host = '169.254.10.1'
port = 5000

global sock
global price 

def listen_for_new_peer(host, port):
    sock  = SocketServer(host, port)
    sock.listen()
    return sock

def increase():
    global price
    global sock
    
    new_price = price.get()+1
    price.set(new_price)
    sock.send(new_price.to_bytes(4, 'little'))

def decrease():
    global price
    global sock

    val = price.get()

    if(val ==0):
        pass
    else:
        new_price = val-1
        price.set(new_price)
        sock.send(new_price.to_bytes(4, 'little'))
        


sock = listen_for_new_peer(host, port)


# Create the main window
root = tk.Tk()
root.title("Node B: Router")

# Create the main container
frame = tk.Frame(root)

# Lay out the main container, specify that we want it to grow with window size
frame.pack(fill=tk.BOTH, expand=True)

# Allow middle cell of grid to grow when window is resized
frame.columnconfigure(2, weight=1)
frame.rowconfigure(3, weight=1)
frame.rowconfigure(5, weight=1)


# Variables for holding temperature data
price = tk.IntVar()
totalBalance = tk.IntVar()
channel_B_local = tk.IntVar()
channel_D_local = tk.IntVar()

totalBalance.set(1000)
channel_B_local.set(2000)
channel_D_local.set(3000)

# Create widgets
button_up = tk.Button(frame, text="Up", command=increase)
label_size = tk.Label(frame, textvariable = price)
label_unit_packet = tk.Label(frame, text="bytes")
button_down = tk.Button(frame, text="Down", command=decrease)
label_wallet_balance_label = tk.Label(frame, text="Total Wallet Balance:", font=('Helvetica', 13, 'bold'))
label_wallet_balance = tk.Label(frame, textvariable = totalBalance)
label_chan_B_balance = tk.Label(frame, text="Channel A-B Local Balance:", font=('Helvetica', 13, 'bold'))
label_chan_B_label = tk.Label(frame, textvariable = channel_B_local)
label_chan_D_balance = tk.Label(frame, text="Channel A-D Local Balance:", font=('Helvetica', 13, 'bold'))
label_chan_D_label = tk.Label(frame, textvariable = channel_D_local)
label_status = tk.Label(frame, text="SENDING...", font=('Helvetica', 15, 'bold'))


# Lay out widgets
label_size.grid(row=1, column=3, padx=5, pady=5)
label_unit_packet.grid(row=1, column=4, padx=5, pady=5)
button_up.grid(row=0, column=3, columnspan=2, padx=5, pady=5)
button_down.grid(row=2, column=3, columnspan=2, padx=5, pady=5)
label_wallet_balance_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
label_wallet_balance.grid(row=0, column=1, padx=5, pady=5)
label_chan_B_balance.grid(row=1, column=0, padx=5, pady=5)
label_chan_B_label.grid(row=1, column=1, padx=5, pady=5)
label_chan_D_balance.grid(row=2, column=0, padx=5, pady=5)
label_chan_D_label.grid(row=2, column=1, padx=5, pady=5)
label_status.grid(row=4, column=0, columnspan=3, padx=5, pady=5)

# Run forever!
root.mainloop()

