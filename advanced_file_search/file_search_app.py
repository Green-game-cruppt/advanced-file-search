#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
File Search Application
A GUI application to search for keywords in specified files
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import re
import os
from typing import List, Tuple, Optional

class FileSearchApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Search Tool")
        self.root.geometry("800x600")
        
        # Variables
        self.selected_file = tk.StringVar()
        self.search_keyword = tk.StringVar()
        self.case_sensitive = tk.BooleanVar()
        self.use_regex = tk.BooleanVar()
        self.whole_word = tk.BooleanVar()
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the user interface"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=1)
        
        # File selection section
        ttk.Label(main_frame, text="Select File:").grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        
        file_frame = ttk.Frame(main_frame)
        file_frame.grid(row=0, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 5))
        file_frame.columnconfigure(0, weight=1)
        
        self.file_entry = ttk.Entry(file_frame, textvariable=self.selected_file, state="readonly")
        self.file_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        
        ttk.Button(file_frame, text="Browse", command=self.browse_file).grid(row=0, column=1)
        
        # Search keyword section
        ttk.Label(main_frame, text="Search Keyword:").grid(row=1, column=0, sticky=tk.W, pady=(10, 5))
        
        self.keyword_entry = ttk.Entry(main_frame, textvariable=self.search_keyword)
        self.keyword_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=(10, 5), padx=(0, 5))
        
        ttk.Button(main_frame, text="Search", command=self.search_file).grid(row=1, column=2, pady=(10, 5))
        
        # Search options section
        options_frame = ttk.LabelFrame(main_frame, text="Search Options", padding="5")
        options_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 5))
        
        ttk.Checkbutton(options_frame, text="Case Sensitive", variable=self.case_sensitive).grid(row=0, column=0, sticky=tk.W)
        ttk.Checkbutton(options_frame, text="Use Regular Expression", variable=self.use_regex).grid(row=0, column=1, sticky=tk.W, padx=(20, 0))
        ttk.Checkbutton(options_frame, text="Whole Word Only", variable=self.whole_word).grid(row=0, column=2, sticky=tk.W, padx=(20, 0))
        
        # Results section
        results_frame = ttk.LabelFrame(main_frame, text="Search Results", padding="5")
        results_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 5))
        results_frame.columnconfigure(0, weight=1)
        
        # Results summary
        self.results_label = ttk.Label(results_frame, text="No search performed yet")
        self.results_label.grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        
        # Results display area
        results_display_frame = ttk.Frame(main_frame)
        results_display_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(5, 0))
        results_display_frame.columnconfigure(0, weight=1)
        results_display_frame.rowconfigure(0, weight=1)
        
        # Text widget with scrollbar for results
        self.results_text = scrolledtext.ScrolledText(
            results_display_frame, 
            wrap=tk.WORD, 
            height=15,
            font=('Courier', 10)
        )
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure text tags for highlighting
        self.results_text.tag_configure("highlight", background="yellow", foreground="black")
        self.results_text.tag_configure("line_number", foreground="blue", font=('Courier', 10, 'bold'))
        self.results_text.tag_configure("context", foreground="gray")
        
        # Bind Enter key to search
        self.keyword_entry.bind('<Return>', lambda event: self.search_file())
        
    def browse_file(self):
        """Open file dialog to select a file"""
        file_path = filedialog.askopenfilename(
            title="Select file to search",
            filetypes=[
                ("Text files", "*.txt"),
                ("Python files", "*.py"),
                ("JavaScript files", "*.js"),
                ("HTML files", "*.html"),
                ("CSS files", "*.css"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            self.selected_file.set(file_path)
            
    def search_file(self):
        """Perform the search operation"""
        file_path = self.selected_file.get().strip()
        keyword = self.search_keyword.get().strip()
        
        # Validation
        if not file_path:
            messagebox.showerror("Error", "Please select a file to search.")
            return
            
        if not keyword:
            messagebox.showerror("Error", "Please enter a keyword to search.")
            return
            
        if not os.path.exists(file_path):
            messagebox.showerror("Error", "Selected file does not exist.")
            return
            
        try:
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                lines = file.readlines()
                
            # Perform search
            matches = self.find_matches(lines, keyword)
            
            # Display results
            self.display_results(matches, keyword, file_path)
            
        except Exception as e:
            messagebox.showerror("Error", f"Error reading file: {str(e)}")
            
    def find_matches(self, lines: List[str], keyword: str) -> List[Tuple[int, str, List[Tuple[int, int]]]]:
        """Find all matches of the keyword in the lines"""
        matches = []
        
        # Prepare search pattern
        if self.use_regex.get():
            try:
                flags = 0 if self.case_sensitive.get() else re.IGNORECASE
                pattern = re.compile(keyword, flags)
            except re.error as e:
                messagebox.showerror("Regex Error", f"Invalid regular expression: {str(e)}")
                return []
        else:
            # Escape special regex characters if not using regex
            escaped_keyword = re.escape(keyword)
            
            if self.whole_word.get():
                escaped_keyword = r'\b' + escaped_keyword + r'\b'
                
            flags = 0 if self.case_sensitive.get() else re.IGNORECASE
            pattern = re.compile(escaped_keyword, flags)
            
        # Search through lines
        for line_num, line in enumerate(lines, 1):
            line_matches = []
            for match in pattern.finditer(line):
                line_matches.append((match.start(), match.end()))
                
            if line_matches:
                matches.append((line_num, line.rstrip('\n'), line_matches))
                
        return matches
        
    def display_results(self, matches: List[Tuple[int, str, List[Tuple[int, int]]]], keyword: str, file_path: str):
        """Display search results in the text widget"""
        # Clear previous results
        self.results_text.delete(1.0, tk.END)
        
        # Update results summary
        total_matches = sum(len(line_matches) for _, _, line_matches in matches)
        self.results_label.config(
            text=f"Found {total_matches} matches in {len(matches)} lines in file: {os.path.basename(file_path)}"
        )
        
        if not matches:
            self.results_text.insert(tk.END, "No matches found.")
            return
            
        # Display matches
        for line_num, line_content, line_matches in matches:
            # Insert line number
            line_start = self.results_text.index(tk.END)
            self.results_text.insert(tk.END, f"Line {line_num}: ")
            line_num_end = self.results_text.index(tk.END)
            self.results_text.tag_add("line_number", line_start, line_num_end)
            
            # Insert line content with highlighting
            content_start = self.results_text.index(tk.END)
            self.results_text.insert(tk.END, line_content + "\n")
            
            # Highlight matches in this line
            for match_start, match_end in line_matches:
                # Calculate positions in the text widget
                highlight_start = f"{content_start}+{match_start}c"
                highlight_end = f"{content_start}+{match_end}c"
                self.results_text.tag_add("highlight", highlight_start, highlight_end)
                
            self.results_text.insert(tk.END, "\n")
            
        # Scroll to top
        self.results_text.see(1.0)

def main():
    """Main function to run the application"""
    root = tk.Tk()
    app = FileSearchApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
