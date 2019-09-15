from tkinter import *
root = Tk()
root.configure(bg="#99B898")
root.wm_title("Hello World")
root.attributes("-fullscreen", True) 

def end_fullscreen(event):
    root.attributes("-fullscreen", False)




root.bind("<Escape>, end_fullscreen")
root.mainloop()

