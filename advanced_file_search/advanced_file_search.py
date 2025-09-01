#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced File Search Application
Enhanced version with additional features like context display, export results, search history
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import re
import os
import json
import logging
import traceback
from datetime import datetime
from typing import List, Tuple, Optional, Dict

# Debug and error handling support
class DebugManager:
    def __init__(self):
        self.setup_logging()
        self.error_patterns = {
            'encoding': [r'UnicodeDecodeError', r'codec can\'t decode'],
            'permission': [r'PermissionError', r'Access is denied'],
            'file_not_found': [r'FileNotFoundError', r'No such file'],
            'regex_error': [r'error: ', r'Invalid regular expression'],
            'memory': [r'MemoryError', r'out of memory']
        }
        self.auto_fixes = {
            'encoding': 'Try different encoding (utf-8, gbk, latin-1)',
            'permission': 'Check file permissions or run as administrator',
            'file_not_found': 'Verify file path exists and is accessible',
            'regex_error': 'Check regular expression syntax',
            'memory': 'Try searching smaller files or use filters'
        }
    
    def setup_logging(self):
        log_dir = os.path.join(os.path.expanduser('~'), '.file_search_logs')
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, f'debug_{datetime.now().strftime("%Y%m%d")}.log')
        
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file, encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def log_error(self, error, context=''):
        error_msg = f"Error in {context}: {str(error)}"
        self.logger.error(error_msg)
        self.logger.debug(traceback.format_exc())
        return error_msg
    
    def analyze_error(self, error_text):
        suggestions = []
        error_type = 'unknown'
        
        for error_category, patterns in self.error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, str(error_text), re.IGNORECASE):
                    error_type = error_category
                    suggestions.append(self.auto_fixes[error_category])
                    break
            if error_type != 'unknown':
                break
        
        return error_type, suggestions
    
    def get_system_info(self):
        import platform
        import sys
        return {
            'platform': platform.platform(),
            'python_version': sys.version,
            'encoding': sys.getdefaultencoding()
        }

# Language support
class LanguageManager:
    def __init__(self):
        self.current_language = 'en'  # Default to English
        self.translations = {
            'en': {
                'title': 'Advanced File Search Tool',
                'search_tab': 'Search',
                'history_tab': 'History',
                'debug_tab': 'Debug',
                'select_file': 'Select File:',
                'browse': 'Browse',
                'search_keyword': 'Search Keyword:',
                'search': 'Search',
                'clear': 'Clear',
                'search_options': 'Search Options',
                'case_sensitive': 'Case Sensitive',
                'use_regex': 'Use Regular Expression',
                'whole_word': 'Whole Word Only',
                'show_context': 'Show Context',
                'context_lines': 'Context Lines:',
                'search_results': 'Search Results',
                'export_results': 'Export Results',
                'no_search': 'No search performed yet',
                'search_history': 'Search History:',
                'clear_history': 'Clear History',
                'refresh': 'Refresh',
                'language': 'Language:',
                'error': 'Error',
                'warning': 'Warning',
                'success': 'Success',
                'confirm': 'Confirm',
                'select_file_error': 'Please select a file to search.',
                'enter_keyword_error': 'Please enter a keyword to search.',
                'file_not_exist_error': 'Selected file does not exist.',
                'read_file_error': 'Error reading file: {}',
                'regex_error': 'Invalid regular expression: {}',
                'no_matches': 'No matches found.',
                'found_matches': 'Found {} matches in {} lines in file: {}',
                'no_results_export': 'No search results to export.',
                'export_success': 'Results exported to {}',
                'export_error': 'Error exporting results: {}',
                'clear_history_confirm': 'Are you sure you want to clear all search history?',
                'loaded_from_history': 'Search parameters loaded from history. Click Search to run.',
                'matches_text': 'matches',
                'auto_debug': 'Auto Debug',
                'show_logs': 'Show Logs',
                'system_info': 'System Info',
                'error_analysis': 'Error Analysis',
                'debug_info': 'Debug Information',
                'error_detected': 'Error Detected',
                'suggested_fixes': 'Suggested Fixes',
                'logs_exported': 'Debug logs exported successfully'
            },
            'zh': {
                'title': '高级文件搜索工具',
                'search_tab': '搜索',
                'history_tab': '历史记录',
                'debug_tab': '调试',
                'select_file': '选择文件：',
                'browse': '浏览',
                'search_keyword': '搜索关键字：',
                'search': '搜索',
                'clear': '清除',
                'search_options': '搜索选项',
                'case_sensitive': '区分大小写',
                'use_regex': '使用正则表达式',
                'whole_word': '仅匹配整词',
                'show_context': '显示上下文',
                'context_lines': '上下文行数：',
                'search_results': '搜索结果',
                'export_results': '导出结果',
                'no_search': '尚未执行搜索',
                'search_history': '搜索历史：',
                'clear_history': '清除历史',
                'refresh': '刷新',
                'language': '语言：',
                'error': '错误',
                'warning': '警告',
                'success': '成功',
                'confirm': '确认',
                'select_file_error': '请选择要搜索的文件。',
                'enter_keyword_error': '请输入要搜索的关键字。',
                'file_not_exist_error': '选择的文件不存在。',
                'read_file_error': '读取文件时出错：{}',
                'regex_error': '无效的正则表达式：{}',
                'no_matches': '未找到匹配项。',
                'found_matches': '在文件 {} 中找到 {} 个匹配项，共 {} 行',
                'no_results_export': '没有搜索结果可导出。',
                'export_success': '结果已导出到 {}',
                'export_error': '导出结果时出错：{}',
                'clear_history_confirm': '确定要清除所有搜索历史吗？',
                'loaded_from_history': '已从历史记录加载搜索参数。点击搜索开始运行。',
                'matches_text': '个匹配项',
                'auto_debug': '自动调试',
                'show_logs': '显示日志',
                'system_info': '系统信息',
                'error_analysis': '错误分析',
                'debug_info': '调试信息',
                'error_detected': '检测到错误',
                'suggested_fixes': '建议修复方案',
                'logs_exported': '调试日志导出成功'
            }
        }
    
    def get_text(self, key):
        return self.translations[self.current_language].get(key, key)
    
    def set_language(self, language):
        if language in self.translations:
            self.current_language = language

class AdvancedFileSearchApp:
    def __init__(self, root):
        self.root = root
        self.lang_manager = LanguageManager()
        self.debug_manager = DebugManager()
        self.root.title(self.lang_manager.get_text('title'))
        self.root.geometry("1000x700")
        
        # Variables
        self.selected_file = tk.StringVar()
        self.search_keyword = tk.StringVar()
        self.case_sensitive = tk.BooleanVar()
        self.use_regex = tk.BooleanVar()
        self.whole_word = tk.BooleanVar()
        self.show_context = tk.BooleanVar(value=True)
        self.context_lines = tk.IntVar(value=2)
        self.current_language = tk.StringVar(value='en')
        
        # Search history
        self.search_history = []
        self.history_file = "search_history.json"
        self.load_search_history()
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the user interface"""
        # Language selection frame
        lang_frame = ttk.Frame(self.root)
        lang_frame.pack(fill=tk.X, padx=10, pady=(10, 0))
        
        ttk.Label(lang_frame, text=self.lang_manager.get_text('language')).pack(side=tk.LEFT)
        
        self.language_combo = ttk.Combobox(
            lang_frame, 
            textvariable=self.current_language,
            values=['en', 'zh'],
            state='readonly',
            width=10
        )
        self.language_combo.pack(side=tk.LEFT, padx=(5, 0))
        self.language_combo.bind('<<ComboboxSelected>>', self.change_language)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Main search tab
        self.search_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.search_frame, text=self.lang_manager.get_text('search_tab'))
        
        # History tab
        self.history_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.history_frame, text=self.lang_manager.get_text('history_tab'))
        
        # Debug tab
        self.debug_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.debug_frame, text=self.lang_manager.get_text('debug_tab'))
        
        self.setup_search_tab()
        self.setup_history_tab()
        self.setup_debug_tab()
        
    def setup_search_tab(self):
        """Setup the main search tab"""
        main_frame = ttk.Frame(self.search_frame, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Configure grid weights
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(6, weight=1)
        
        # File selection section
        self.file_label = ttk.Label(main_frame, text=self.lang_manager.get_text('select_file'))
        self.file_label.grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        
        file_frame = ttk.Frame(main_frame)
        file_frame.grid(row=0, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 5))
        file_frame.columnconfigure(0, weight=1)
        
        self.file_entry = ttk.Entry(file_frame, textvariable=self.selected_file, state="readonly")
        self.file_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        
        self.browse_button = ttk.Button(file_frame, text=self.lang_manager.get_text('browse'), command=self.browse_file)
        self.browse_button.grid(row=0, column=1)
        
        # Search keyword section
        self.keyword_label = ttk.Label(main_frame, text=self.lang_manager.get_text('search_keyword'))
        self.keyword_label.grid(row=1, column=0, sticky=tk.W, pady=(10, 5))
        
        keyword_frame = ttk.Frame(main_frame)
        keyword_frame.grid(row=1, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 5))
        keyword_frame.columnconfigure(0, weight=1)
        
        self.keyword_entry = ttk.Entry(keyword_frame, textvariable=self.search_keyword)
        self.keyword_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        
        self.search_button = ttk.Button(keyword_frame, text=self.lang_manager.get_text('search'), command=self.search_file)
        self.search_button.grid(row=0, column=1, padx=(0, 5))
        self.clear_button = ttk.Button(keyword_frame, text=self.lang_manager.get_text('clear'), command=self.clear_results)
        self.clear_button.grid(row=0, column=2)
        
        # Search options section
        self.options_frame = ttk.LabelFrame(main_frame, text=self.lang_manager.get_text('search_options'), padding="5")
        self.options_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 5))
        
        # First row of options
        self.case_check = ttk.Checkbutton(self.options_frame, text=self.lang_manager.get_text('case_sensitive'), variable=self.case_sensitive)
        self.case_check.grid(row=0, column=0, sticky=tk.W)
        self.regex_check = ttk.Checkbutton(self.options_frame, text=self.lang_manager.get_text('use_regex'), variable=self.use_regex)
        self.regex_check.grid(row=0, column=1, sticky=tk.W, padx=(20, 0))
        self.word_check = ttk.Checkbutton(self.options_frame, text=self.lang_manager.get_text('whole_word'), variable=self.whole_word)
        self.word_check.grid(row=0, column=2, sticky=tk.W, padx=(20, 0))
        
        # Second row of options
        self.context_check = ttk.Checkbutton(self.options_frame, text=self.lang_manager.get_text('show_context'), variable=self.show_context)
        self.context_check.grid(row=1, column=0, sticky=tk.W, pady=(5, 0))
        
        context_frame = ttk.Frame(self.options_frame)
        context_frame.grid(row=1, column=1, sticky=tk.W, padx=(20, 0), pady=(5, 0))
        
        self.context_label = ttk.Label(context_frame, text=self.lang_manager.get_text('context_lines'))
        self.context_label.pack(side=tk.LEFT)
        context_spinbox = ttk.Spinbox(context_frame, from_=0, to=10, width=5, textvariable=self.context_lines)
        context_spinbox.pack(side=tk.LEFT, padx=(5, 0))
        
        # Results section
        self.results_frame = ttk.LabelFrame(main_frame, text=self.lang_manager.get_text('search_results'), padding="5")
        self.results_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 5))
        self.results_frame.columnconfigure(0, weight=1)
        
        # Results summary and export button
        summary_frame = ttk.Frame(self.results_frame)
        summary_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        summary_frame.columnconfigure(0, weight=1)
        
        self.results_label = ttk.Label(summary_frame, text=self.lang_manager.get_text('no_search'))
        self.results_label.grid(row=0, column=0, sticky=tk.W)
        
        self.export_button = ttk.Button(summary_frame, text=self.lang_manager.get_text('export_results'), command=self.export_results)
        self.export_button.grid(row=0, column=1, padx=(10, 0))
        
        # Results display area
        results_display_frame = ttk.Frame(main_frame)
        results_display_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(5, 0))
        results_display_frame.columnconfigure(0, weight=1)
        results_display_frame.rowconfigure(0, weight=1)
        
        # Text widget with scrollbar for results
        self.results_text = scrolledtext.ScrolledText(
            results_display_frame, 
            wrap=tk.WORD, 
            height=20,
            font=('Courier', 10)
        )
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure text tags for highlighting
        self.results_text.tag_configure("highlight", background="yellow", foreground="black")
        self.results_text.tag_configure("line_number", foreground="blue", font=('Courier', 10, 'bold'))
        self.results_text.tag_configure("context", foreground="gray")
        self.results_text.tag_configure("separator", foreground="red", font=('Courier', 10, 'bold'))
        
        # Bind Enter key to search
        self.keyword_entry.bind('<Return>', lambda event: self.search_file())
        
        # Store current search results for export
        self.current_results = []
        
    def setup_history_tab(self):
        """Setup the search history tab"""
        history_main_frame = ttk.Frame(self.history_frame, padding="10")
        history_main_frame.pack(fill=tk.BOTH, expand=True)
        
        # History controls
        controls_frame = ttk.Frame(history_main_frame)
        controls_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.history_label = ttk.Label(controls_frame, text=self.lang_manager.get_text('search_history'))
        self.history_label.pack(side=tk.LEFT)
        self.clear_history_button = ttk.Button(controls_frame, text=self.lang_manager.get_text('clear_history'), command=self.clear_history)
        self.clear_history_button.pack(side=tk.RIGHT)
        self.refresh_button = ttk.Button(controls_frame, text=self.lang_manager.get_text('refresh'), command=self.refresh_history)
        self.refresh_button.pack(side=tk.RIGHT, padx=(0, 5))
        
        # History listbox
        history_frame = ttk.Frame(history_main_frame)
        history_frame.pack(fill=tk.BOTH, expand=True)
        
        # Listbox with scrollbar
        listbox_frame = ttk.Frame(history_frame)
        listbox_frame.pack(fill=tk.BOTH, expand=True)
        
        self.history_listbox = tk.Listbox(listbox_frame, font=('Courier', 10))
        history_scrollbar = ttk.Scrollbar(listbox_frame, orient=tk.VERTICAL, command=self.history_listbox.yview)
        self.history_listbox.configure(yscrollcommand=history_scrollbar.set)
        
        self.history_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        history_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind double-click to load search
        self.history_listbox.bind('<Double-1>', self.load_from_history)
        
        self.refresh_history()
        
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
                ("JSON files", "*.json"),
                ("XML files", "*.xml"),
                ("Log files", "*.log"),
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
            messagebox.showerror(self.lang_manager.get_text('error'), self.lang_manager.get_text('select_file_error'))
            return
            
        if not keyword:
            messagebox.showerror(self.lang_manager.get_text('error'), self.lang_manager.get_text('enter_keyword_error'))
            return
            
        if not os.path.exists(file_path):
            messagebox.showerror(self.lang_manager.get_text('error'), self.lang_manager.get_text('file_not_exist_error'))
            return
            
        try:
            # Read file content with multiple encoding attempts
            lines = self.read_file_with_fallback(file_path)
                
            # Perform search
            matches = self.find_matches(lines, keyword)
            
            # Display results
            self.display_results(matches, keyword, file_path, lines)
            
            # Save to history
            self.save_to_history(file_path, keyword, len(matches))
            
        except Exception as e:
            error_msg = self.debug_manager.log_error(e, 'search_file')
            error_type, suggestions = self.debug_manager.analyze_error(str(e))
            
            # Show error with suggestions
            error_details = f"{self.lang_manager.get_text('read_file_error').format(str(e))}\n\n"
            if suggestions:
                error_details += f"{self.lang_manager.get_text('suggested_fixes')}:\n"
                for suggestion in suggestions:
                    error_details += f"• {suggestion}\n"
            
            messagebox.showerror(self.lang_manager.get_text('error'), error_details)
            self.update_debug_info(error_msg, error_type, suggestions)
            
    def find_matches(self, lines: List[str], keyword: str) -> List[Tuple[int, str, List[Tuple[int, int]]]]:
        """Find all matches of the keyword in the lines"""
        matches = []
        
        # Prepare search pattern
        if self.use_regex.get():
            try:
                flags = 0 if self.case_sensitive.get() else re.IGNORECASE
                pattern = re.compile(keyword, flags)
            except re.error as e:
                messagebox.showerror(self.lang_manager.get_text('error'), self.lang_manager.get_text('regex_error').format(str(e)))
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
        
    def display_results(self, matches: List[Tuple[int, str, List[Tuple[int, int]]]], keyword: str, file_path: str, all_lines: List[str]):
        """Display search results in the text widget"""
        # Clear previous results
        self.results_text.delete(1.0, tk.END)
        
        # Store current results for export
        self.current_results = {
            'file_path': file_path,
            'keyword': keyword,
            'matches': matches,
            'timestamp': datetime.now().isoformat(),
            'options': {
                'case_sensitive': self.case_sensitive.get(),
                'use_regex': self.use_regex.get(),
                'whole_word': self.whole_word.get(),
                'show_context': self.show_context.get(),
                'context_lines': self.context_lines.get()
            }
        }
        
        # Update results summary
        total_matches = sum(len(line_matches) for _, _, line_matches in matches)
        if self.lang_manager.current_language == 'zh':
            self.results_label.config(
                text=self.lang_manager.get_text('found_matches').format(os.path.basename(file_path), total_matches, len(matches))
            )
        else:
            self.results_label.config(
                text=self.lang_manager.get_text('found_matches').format(total_matches, len(matches), os.path.basename(file_path))
            )
        
        if not matches:
            self.results_text.insert(tk.END, self.lang_manager.get_text('no_matches'))
            return
            
        # Display matches with context if enabled
        context_lines_count = self.context_lines.get() if self.show_context.get() else 0
        
        for i, (line_num, line_content, line_matches) in enumerate(matches):
            if i > 0:
                self.results_text.insert(tk.END, "\n" + "-" * 80 + "\n\n")
                
            # Show context before
            if context_lines_count > 0:
                start_context = max(0, line_num - context_lines_count - 1)
                for ctx_line_num in range(start_context, line_num - 1):
                    if ctx_line_num < len(all_lines):
                        ctx_start = self.results_text.index(tk.END)
                        self.results_text.insert(tk.END, f"  {ctx_line_num + 1}: {all_lines[ctx_line_num].rstrip()}\n")
                        ctx_end = self.results_text.index(tk.END)
                        self.results_text.tag_add("context", ctx_start, ctx_end)
                        
            # Insert main match line
            line_start = self.results_text.index(tk.END)
            self.results_text.insert(tk.END, f"► {line_num}: ")
            line_num_end = self.results_text.index(tk.END)
            self.results_text.tag_add("line_number", line_start, line_num_end)
            
            # Insert line content with highlighting
            content_start = self.results_text.index(tk.END)
            self.results_text.insert(tk.END, line_content + "\n")
            
            # Highlight matches in this line
            for match_start, match_end in line_matches:
                highlight_start = f"{content_start}+{match_start}c"
                highlight_end = f"{content_start}+{match_end}c"
                self.results_text.tag_add("highlight", highlight_start, highlight_end)
                
            # Show context after
            if context_lines_count > 0:
                end_context = min(len(all_lines), line_num + context_lines_count)
                for ctx_line_num in range(line_num, end_context):
                    if ctx_line_num < len(all_lines):
                        ctx_start = self.results_text.index(tk.END)
                        self.results_text.insert(tk.END, f"  {ctx_line_num + 1}: {all_lines[ctx_line_num].rstrip()}\n")
                        ctx_end = self.results_text.index(tk.END)
                        self.results_text.tag_add("context", ctx_start, ctx_end)
                        
        # Scroll to top
        self.results_text.see(1.0)
        
    def clear_results(self):
        """Clear search results"""
        self.results_text.delete(1.0, tk.END)
        self.results_label.config(text=self.lang_manager.get_text('no_search'))
        self.current_results = []
        
    def export_results(self):
        """Export search results to a file"""
        if not self.current_results:
            messagebox.showwarning(self.lang_manager.get_text('warning'), self.lang_manager.get_text('no_results_export'))
            return
            
        file_path = filedialog.asksaveasfilename(
            title="Export search results",
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("JSON files", "*.json"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            try:
                if file_path.endswith('.json'):
                    with open(file_path, 'w', encoding='utf-8') as f:
                        json.dump(self.current_results, f, indent=2, ensure_ascii=False)
                else:
                    # Export as text
                    content = self.results_text.get(1.0, tk.END)
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(f"Search Results Export\n")
                        f.write(f"File: {self.current_results['file_path']}\n")
                        f.write(f"Keyword: {self.current_results['keyword']}\n")
                        f.write(f"Timestamp: {self.current_results['timestamp']}\n")
                        f.write(f"{'=' * 80}\n\n")
                        f.write(content)
                        
                messagebox.showinfo(self.lang_manager.get_text('success'), self.lang_manager.get_text('export_success').format(file_path))
            except Exception as e:
                messagebox.showerror(self.lang_manager.get_text('error'), self.lang_manager.get_text('export_error').format(str(e)))
                
    def save_to_history(self, file_path: str, keyword: str, match_count: int):
        """Save search to history"""
        history_entry = {
            'timestamp': datetime.now().isoformat(),
            'file_path': file_path,
            'keyword': keyword,
            'match_count': match_count,
            'options': {
                'case_sensitive': self.case_sensitive.get(),
                'use_regex': self.use_regex.get(),
                'whole_word': self.whole_word.get()
            }
        }
        
        self.search_history.insert(0, history_entry)
        
        # Keep only last 100 searches
        if len(self.search_history) > 100:
            self.search_history = self.search_history[:100]
            
        self.save_search_history()
        self.refresh_history()
        
    def load_search_history(self):
        """Load search history from file"""
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    self.search_history = json.load(f)
        except Exception:
            self.search_history = []
            
    def save_search_history(self):
        """Save search history to file"""
        try:
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(self.search_history, f, indent=2, ensure_ascii=False)
        except Exception:
            pass
            
    def refresh_history(self):
        """Refresh the history listbox"""
        self.history_listbox.delete(0, tk.END)
        
        for entry in self.search_history:
            timestamp = datetime.fromisoformat(entry['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            file_name = os.path.basename(entry['file_path'])
            keyword = entry['keyword'][:30] + '...' if len(entry['keyword']) > 30 else entry['keyword']
            match_count = entry['match_count']
            
            display_text = f"{timestamp} | {file_name} | '{keyword}' | {match_count} matches"
            self.history_listbox.insert(tk.END, display_text)
            
    def load_from_history(self, event):
        """Load a search from history"""
        selection = self.history_listbox.curselection()
        if selection:
            index = selection[0]
            if index < len(self.search_history):
                entry = self.search_history[index]
                
                # Load search parameters
                self.selected_file.set(entry['file_path'])
                self.search_keyword.set(entry['keyword'])
                
                if 'options' in entry:
                    self.case_sensitive.set(entry['options'].get('case_sensitive', False))
                    self.use_regex.set(entry['options'].get('use_regex', False))
                    self.whole_word.set(entry['options'].get('whole_word', False))
                    
                # Switch to search tab
                # Note: This would require access to the notebook widget
                messagebox.showinfo(self.lang_manager.get_text('success'), self.lang_manager.get_text('loaded_from_history'))
                
    def clear_history(self):
        """Clear search history"""
        if messagebox.askyesno(self.lang_manager.get_text('confirm'), self.lang_manager.get_text('clear_history_confirm')):
            self.search_history = []
            self.save_search_history()
            self.refresh_history()
    
    def change_language(self, event=None):
        """Change the application language"""
        new_language = self.current_language.get()
        self.lang_manager.set_language(new_language)
        self.update_ui_language()
    
    def update_ui_language(self):
        """Update all UI elements with the new language"""
        # Update window title
        self.root.title(self.lang_manager.get_text('title'))
        
        # Update tab names
        self.notebook.tab(0, text=self.lang_manager.get_text('search_tab'))
        self.notebook.tab(1, text=self.lang_manager.get_text('history_tab'))
        
        # Update search tab elements
        self.file_label.config(text=self.lang_manager.get_text('select_file'))
        self.browse_button.config(text=self.lang_manager.get_text('browse'))
        self.keyword_label.config(text=self.lang_manager.get_text('search_keyword'))
        self.search_button.config(text=self.lang_manager.get_text('search'))
        self.clear_button.config(text=self.lang_manager.get_text('clear'))
        
        # Update options frame
        self.options_frame.config(text=self.lang_manager.get_text('search_options'))
        self.case_check.config(text=self.lang_manager.get_text('case_sensitive'))
        self.regex_check.config(text=self.lang_manager.get_text('use_regex'))
        self.word_check.config(text=self.lang_manager.get_text('whole_word'))
        self.context_check.config(text=self.lang_manager.get_text('show_context'))
        self.context_label.config(text=self.lang_manager.get_text('context_lines'))
        
        # Update results frame
        self.results_frame.config(text=self.lang_manager.get_text('search_results'))
        self.export_button.config(text=self.lang_manager.get_text('export_results'))
        
        # Update history tab elements
        self.history_label.config(text=self.lang_manager.get_text('search_history'))
        self.clear_history_button.config(text=self.lang_manager.get_text('clear_history'))
        self.refresh_button.config(text=self.lang_manager.get_text('refresh'))
        
        # Update debug tab elements
        self.notebook.tab(2, text=self.lang_manager.get_text('debug_tab'))
        self.auto_debug_check.config(text=self.lang_manager.get_text('auto_debug'))
        self.show_logs_button.config(text=self.lang_manager.get_text('show_logs'))
        self.system_info_button.config(text=self.lang_manager.get_text('system_info'))
        
        # Update results label if no search has been performed
        if self.results_label.cget('text') in ['No search performed yet', '尚未执行搜索']:
            self.results_label.config(text=self.lang_manager.get_text('no_search'))

    def read_file_with_fallback(self, file_path):
        """Try to read file with multiple encodings"""
        encodings = ['utf-8', 'gbk', 'gb2312', 'latin-1', 'cp1252']
        
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding, errors='ignore') as file:
                    lines = file.readlines()
                self.debug_manager.logger.info(f"Successfully read file with {encoding} encoding")
                return lines
            except UnicodeDecodeError:
                continue
        
        # If all encodings fail, try binary mode
        try:
            with open(file_path, 'rb') as file:
                content = file.read().decode('utf-8', errors='replace')
                lines = content.splitlines(True)
            self.debug_manager.logger.warning("Used binary mode with error replacement")
            return lines
        except Exception as e:
            self.debug_manager.log_error(e, 'read_file_with_fallback')
            raise
    
    def setup_debug_tab(self):
        """Setup the debug tab"""
        debug_main_frame = ttk.Frame(self.debug_frame, padding="10")
        debug_main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Debug controls
        controls_frame = ttk.Frame(debug_main_frame)
        controls_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.auto_debug_var = tk.BooleanVar(value=True)
        self.auto_debug_check = ttk.Checkbutton(
            controls_frame, 
            text=self.lang_manager.get_text('auto_debug'),
            variable=self.auto_debug_var
        )
        self.auto_debug_check.pack(side=tk.LEFT)
        
        self.show_logs_button = ttk.Button(
            controls_frame, 
            text=self.lang_manager.get_text('show_logs'),
            command=self.show_debug_logs
        )
        self.show_logs_button.pack(side=tk.RIGHT, padx=(5, 0))
        
        self.system_info_button = ttk.Button(
            controls_frame, 
            text=self.lang_manager.get_text('system_info'),
            command=self.show_system_info
        )
        self.system_info_button.pack(side=tk.RIGHT)
        
        # Debug information display
        debug_info_frame = ttk.LabelFrame(
            debug_main_frame, 
            text=self.lang_manager.get_text('debug_info'),
            padding="5"
        )
        debug_info_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        self.debug_text = scrolledtext.ScrolledText(
            debug_info_frame,
            wrap=tk.WORD,
            height=20,
            font=('Courier', 10)
        )
        self.debug_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure text tags
        self.debug_text.tag_configure("error", foreground="red", font=('Courier', 10, 'bold'))
        self.debug_text.tag_configure("warning", foreground="orange")
        self.debug_text.tag_configure("info", foreground="blue")
        self.debug_text.tag_configure("suggestion", foreground="green")
    
    def update_debug_info(self, error_msg, error_type, suggestions):
        """Update debug information display"""
        if not self.auto_debug_var.get():
            return
            
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Add error information
        self.debug_text.insert(tk.END, f"\n[{timestamp}] ", "info")
        self.debug_text.insert(tk.END, f"{self.lang_manager.get_text('error_detected')}: ", "error")
        self.debug_text.insert(tk.END, f"{error_type}\n")
        self.debug_text.insert(tk.END, f"Details: {error_msg}\n")
        
        # Add suggestions
        if suggestions:
            self.debug_text.insert(tk.END, f"\n{self.lang_manager.get_text('suggested_fixes')}:\n", "suggestion")
            for suggestion in suggestions:
                self.debug_text.insert(tk.END, f"• {suggestion}\n", "suggestion")
        
        self.debug_text.insert(tk.END, "\n" + "-" * 80 + "\n")
        self.debug_text.see(tk.END)
    
    def show_debug_logs(self):
        """Export and show debug logs"""
        try:
            log_dir = os.path.join(os.path.expanduser('~'), '.file_search_logs')
            log_file = os.path.join(log_dir, f'debug_{datetime.now().strftime("%Y%m%d")}.log')
            
            if os.path.exists(log_file):
                # Export logs to a user-selected location
                export_path = filedialog.asksaveasfilename(
                    title="Export Debug Logs",
                    defaultextension=".log",
                    filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
                )
                
                if export_path:
                    import shutil
                    shutil.copy2(log_file, export_path)
                    messagebox.showinfo(
                        self.lang_manager.get_text('success'),
                        self.lang_manager.get_text('logs_exported')
                    )
            else:
                messagebox.showwarning(
                    self.lang_manager.get_text('warning'),
                    "No debug logs found for today."
                )
        except Exception as e:
            self.debug_manager.log_error(e, 'show_debug_logs')
            messagebox.showerror(
                self.lang_manager.get_text('error'),
                f"Error exporting logs: {str(e)}"
            )
    
    def show_system_info(self):
        """Show system information"""
        try:
            system_info = self.debug_manager.get_system_info()
            
            info_text = f"{self.lang_manager.get_text('system_info')}:\n\n"
            for key, value in system_info.items():
                info_text += f"{key}: {value}\n"
            
            # Create a new window to display system info
            info_window = tk.Toplevel(self.root)
            info_window.title(self.lang_manager.get_text('system_info'))
            info_window.geometry("600x400")
            
            info_text_widget = scrolledtext.ScrolledText(
                info_window,
                wrap=tk.WORD,
                font=('Courier', 10)
            )
            info_text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            info_text_widget.insert(tk.END, info_text)
            info_text_widget.config(state=tk.DISABLED)
            
        except Exception as e:
            self.debug_manager.log_error(e, 'show_system_info')
            messagebox.showerror(
                self.lang_manager.get_text('error'),
                f"Error getting system info: {str(e)}"
            )

def main():
    """Main function to run the application"""
    root = tk.Tk()
    app = AdvancedFileSearchApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()