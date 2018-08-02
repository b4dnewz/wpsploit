import re
from utils import utils

class rules(object):
    
    # Check for Cross Site Request Forgery
    # https://github.com/ethicalhack3r/wordpress_plugin_security_testing_cheat_sheet#cross-site-request-forgery-csrf
    @staticmethod
    def csrf(code):
        blacklist = [r'wp_nonce_field\(\S*\)', r'wp_nonce_url\(\S*\)',
                     r'wp_verify_nonce\(\S*\)', r'check_admin_referer\(\S*\)']
        vulns = []
        for bl in blacklist:
            for idx, cd in enumerate(code):
                pattern = re.findall(bl, cd, re.I)
                if pattern != []:
                    vulns.append({"line": idx, "match": pattern[0] })
                    utils.printLine(idx, "Cross-Site Request Forgery", pattern[0])
        return vulns
    
    # Check for Open Redirect
    # https://github.com/ethicalhack3r/wordpress_plugin_security_testing_cheat_sheet#open-redirect
    @staticmethod
    def ope(code):
        vulns = []
        for idx, cd in enumerate(code):
            pattern = re.findall(r"wp_redirect\(\S*\)", cd, re.I)
            if pattern != []:
                vulns.append({"line": idx, "match": pattern[0] })
                utils.printLine(idx, "Open Redirect", pattern[0])
        return vulns
        
    # Check for PHP Code Execution
    # https://github.com/ethicalhack3r/wordpress_plugin_security_testing_cheat_sheet#php-code-execution
    @staticmethod
    def pce(code):
        blacklist = [r'eval\(\S*\)', r'assert\(\S*\)', r'preg_replace\(\S*\)']
        vulns = []
        for bl in blacklist:
            for idx, cd in enumerate(code):
                pattern = re.findall(bl, cd, re.I)
                if pattern != []:
                    vulns.append({"line": idx, "match": pattern[0] })
                    utils.printLine(idx, "PHP Code Execution", pattern[0])
        return vulns
    
    # Check for Command Execution
    # https://github.com/ethicalhack3r/wordpress_plugin_security_testing_cheat_sheet#command-execution
    @staticmethod
    def com(code):
        blacklist = [r'system\(\S*\)', r'exec\(\S*\)',
                     r'passthru\(\S*\)', r'shell_exec\(\S*\)']
        vulns = []
        for bl in blacklist:
            for idx, cd in enumerate(code):
                pattern = re.findall(bl, cd, re.I)
                if pattern != []:
                    vulns.append({"line": idx, "match": pattern[0] })
                    utils.printLine(idx, "Command Execution", pattern[0])
        return vulns
    
    # Check for Authorization Hole
    # https://github.com/ethicalhack3r/wordpress_plugin_security_testing_cheat_sheet#authorisation
    @staticmethod
    def auth(code):
        blacklist = [r'is_admin\(\S*\)', r'is_user_admin\(\S*\)']
        vulns = []
        for bl in blacklist:
            for idx, cd in enumerate(code):
                pattern = re.findall(bl, cd, re.I)
                if pattern != []:
                    vulns.append({"line": idx, "match": pattern[0] })
                    utils.printLine(idx, "Authorization Hole", pattern[0])
        return vulns
        
    # Check for PHP Object Injection
    @staticmethod
    def php(code):
        vulns = []
        for idx, cd in enumerate(code):
            pattern = re.findall(r"unserialize\(\S*\)", cd, re.I)
            if pattern != []:
                vulns.append({"line": idx, "match": pattern[0] })
                utils.printLine(idx, "PHP Object Injection", pattern[0])
        return vulns
        
    # Check for File Inclusion
    # https://github.com/ethicalhack3r/wordpress_plugin_security_testing_cheat_sheet#file-inclusion
    @staticmethod
    def fin(code):
        blacklist = [r'include\(\S*\)', r'require\(\S*\)',
                     r'include_once\(\S*\)', r'require_once\(\S*\)', r'fread\(\S*\)']
        vulns = []
        for bl in blacklist:
            for idx, cd in enumerate(code):
                pattern = re.findall(bl, cd, re.I)
                if pattern != []:
                    vulns.append({"line": idx, "match": pattern[0] })
                    utils.printLine(idx, "File Inclusion", pattern[0])
        return vulns
    
    # Check for File Download
    # https://github.com/ethicalhack3r/wordpress_plugin_security_testing_cheat_sheet#file-download
    @staticmethod
    def fid(code):
        blacklist = [r'file\(\S*\)', r'readfile\(\S*\)',
                     r'file_get_contents\(\S*\)']
        vulns = []
        for bl in blacklist:
            for idx, cd in enumerate(code):
                pattern = re.findall(bl, cd, re.I)
                if pattern != []:
                    vulns.append({"line": idx, "match": pattern[0] })
                    utils.printLine(idx, "File Download", pattern[0])
        return vulns
    
    # Check for Sql Injection
    # https://github.com/ethicalhack3r/wordpress_plugin_security_testing_cheat_sheet#sql-injection
    @staticmethod
    def sql(code):
        blacklist = [r'\$wpdb->query\(\S*\)', r'\$wpdb->get_var\(\S*\)', r'\$wpdb->get_row\(\S*\)', r'\$wpdb->get_col\(\S*\)',
                     r'\$wpdb->get_results\(\S*\)', r'\$wpdb->replace\(\S*\)', r'esc_sql\(\S*\)', r'escape\(\S*\)', r'esc_like\(\S*\)',
                     r'like_escape\(\S*\)']
        vulns = []
        for bl in blacklist:
            for idx, cd in enumerate(code):
                pattern = re.findall(bl, cd, re.I)
                if pattern != []:
                    vulns.append({"line": idx, "match": pattern[0] })
                    utils.printLine(idx, "Sql Injection", pattern[0])
        return vulns
    
    # Check for Cross-Site Scripting
    # https://github.com/ethicalhack3r/wordpress_plugin_security_testing_cheat_sheet#cross-site-scripting-xss-tips
    @staticmethod
    def xss(code):
        blacklist = [r'\$_GET\[\S*\]', r'\$_POST\[\S*\]', r'\$_REQUEST\[\S*\]', r'\$_SERVER\[\S*\]', r'\$_COOKIE\[\S*\]',
                     r'add_query_arg\(\S*\)', r'remove_query_arg\(\S*\)']
        vulns = []
        for bl in blacklist:
            for idx, cd in enumerate(code):
                pattern = re.findall(bl, cd, re.I)
                if pattern != []:
                    vulns.append({"line": idx, "match": pattern[0] })
                    utils.printLine(idx, "Cross-Site Scripting", pattern[0])
        return vulns
        