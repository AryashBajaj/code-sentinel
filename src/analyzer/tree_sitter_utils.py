"""Tree-sitter utilities for parsing source code into ASTs."""
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import tree_sitter
from tree_sitter import Language, Parser


class TreeSitterManager:
    """Manages tree-sitter parsers for different languages."""
    
    def __init__(self):
        self.parsers: Dict[str, Parser] = {}
        self.languages: Dict[str, Language] = {}
        self._setup_language_mapping()
    
    def _setup_language_mapping(self):
        """Map file extensions to tree-sitter languages."""
        # This will be populated as we load languages
        self.extension_to_language = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.jsx': 'javascript',
            '.tsx': 'typescript',
        }
    
    def load_language(self, language_name: str) -> bool:
        """
        Load a tree-sitter language.
        
        Args:
            language_name: Name of the language (python, javascript, typescript)
            
        Returns:
            True if language loaded successfully, False otherwise
        """
        try:
            if language_name not in self.languages:
                language = tree_sitter.Language(
                    tree_sitter_languages.language(language_name)
                )
                self.languages[language_name] = language
                
                parser = Parser()
                parser.set_language(language)
                self.parsers[language_name] = parser
            return True
        except Exception as e:
            print(f"Failed to load language {language_name}: {e}")
            return False
    
    def get_parser(self, language_name: str) -> Optional[Parser]:
        """Get parser for a language."""
        return self.parsers.get(language_name)
    
    def get_language(self, language_name: str) -> Optional[Language]:
        """Get language object for a language."""
        return self.languages.get(language_name)
    
    def detect_language_from_extension(self, extension: str) -> Optional[str]:
        """Detect language from file extension."""
        return self.extension_to_language.get(extension.lower())


def parse_file(file_path: Path, manager: TreeSitterManager) -> Tuple[Optional[tree_sitter.Tree], Optional[str]]:
    """
    Parse a source file into an AST.
    
    Args:
        file_path: Path to the source file
        manager: TreeSitterManager instance
        
    Returns:
        Tuple of (AST tree, language name) or (None, None) if parsing failed
    """
    try:
        # Detect language from file extension
        extension = file_path.suffix
        language_name = manager.detect_language_from_extension(extension)
        
        if not language_name:
            return None, None
        
        # Load language if not already loaded
        if not manager.load_language(language_name):
            return None, None
        
        # Get parser
        parser = manager.get_parser(language_name)
        if not parser:
            return None, None
        
        # Read and parse file
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            source_code = f.read()
        
        tree = parser.parse(bytes(source_code, 'utf8'))
        return tree, language_name
        
    except Exception as e:
        print(f"Failed to parse {file_path}: {e}")
        return None, None


def get_node_text(node: tree_sitter.Node, source_code: bytes) -> str:
    """
    Extract the text content of a tree-sitter node.
    
    Args:
        node: Tree-sitter node
        source_code: Original source code as bytes
        
    Returns:
        Text content of the node
    """
    return source_code[node.start_byte:node.end_byte].decode('utf8', errors='ignore')


def walk_tree(tree: tree_sitter.Tree):
    """
    Walk all nodes in a tree-sitter tree.
    
    Args:
        tree: Tree-sitter tree to walk
        
    Yields:
        Each node in the tree
    """
    cursor = tree.walk()
    
    visited_children = False
    while True:
        if not visited_children:
            yield cursor.node
        if cursor.goto_first_child():
            visited_children = True
            continue
        if not cursor.goto_next_sibling():
            if not cursor.goto_parent() or cursor.node == tree.root_node:
                break
            visited_children = False
            continue
        visited_children = False