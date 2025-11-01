# gui.py
import tkinter as tk
from tkinter import filedialog, messagebox
from stego import embed_file, extract_to_file
import os

class App:
    def __init__(self, root):
        self.root = root
        root.title('Stego App - Demo')

        tk.Label(root, text='Cover image:').grid(row=0, column=0)
        self.image_entry = tk.Entry(root, width=50)
        self.image_entry.grid(row=0, column=1)
        tk.Button(root, text='Browse', command=self.browse_image).grid(row=0, column=2)

        tk.Label(root, text='File to hide:').grid(row=1, column=0)
        self.file_entry = tk.Entry(root, width=50)
        self.file_entry.grid(row=1, column=1)
        tk.Button(root, text='Browse', command=self.browse_file).grid(row=1, column=2)

        tk.Label(root, text='Sender ID:').grid(row=2, column=0)
        self.sender_entry = tk.Entry(root, width=30)
        self.sender_entry.grid(row=2, column=1)

        tk.Button(root, text='Embed', command=self.embed).grid(row=3, column=0)
        tk.Button(root, text='Extract', command=self.extract).grid(row=3, column=1)

    def browse_image(self):
        p = filedialog.askopenfilename(filetypes=[('PNG images', '*.png'), ('BMP images', '*.bmp'), ('All', '*.*')])
        if p:
            self.image_entry.delete(0, tk.END)
            self.image_entry.insert(0, p)

    def browse_file(self):
        p = filedialog.askopenfilename()
        if p:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, p)

    def embed(self):
        img = self.image_entry.get()
        infile = self.file_entry.get()
        sender = self.sender_entry.get() or 'gui-user'
        if not img or not infile:
            messagebox.showerror('Error', 'Odaberi sliku i fajl!')
            return
        os.makedirs('output', exist_ok=True)
        out = os.path.join('output', f'stego_{os.path.basename(img)}')
        metadata = {'sender_id': sender}
        try:
            embed_file(img, infile, out, metadata)
            messagebox.showinfo('OK', f'Stego slika sačuvana: {out}')
        except Exception as e:
            messagebox.showerror('Greška', str(e))

    def extract(self):
        img = filedialog.askopenfilename(filetypes=[('PNG images', '*.png'), ('BMP images', '*.bmp')])
        if not img:
            return
        try:
            md, out = extract_to_file(img, 'output')
            messagebox.showinfo('OK', f'Izdvojeno: {out}\nMetadata: {md}')
        except Exception as e:
            messagebox.showerror('Greška', str(e))

if __name__ == '__main__':
    root = tk.Tk()
    app = App(root)
    root.mainloop()
