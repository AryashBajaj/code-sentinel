"""AST converter for tree-sitter.

Converts tree-sitter AST nodes to a generic format that can be analyzed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class GenericASTNode:
    """Generic AST node representation.
    
    Provides a unified interface for analyzing code across different languages.
    """
    node_type: str
    text: str
    start_point: Tuple[int, int]
    end_point: Tuple[int, int]
    children: List[GenericASTNode] = field(default_factory=list)
    parent: Optional[GenericASTNode] = None
    named: bool = True
    
    @property
    def line_number(self) -> int:
        """Get line number (1-indexed)."""
        return self.start_point[0] + 1 if self.start_point else 0
    
    @property
    def column(self) -> int:
        """Get column number (1-indexed)."""
        return self.start_point[1] + 1 if self.start_point else 0
    
    def get_child(self, node_type: str) -> Optional[GenericASTNode]:
        """Get first child of given type."""
        for child in self.children:
            if child.node_type == node_type:
                return child
        return None
    
    def get_children(self, node_type: str) -> List[GenericASTNode]:
        """Get all children of given type."""
        return [child for child in self.children if child.node_type == node_type]
    
    def get_text(self, source: str) -> str:
        """Get the text content of this node from source."""
        start_byte = self._point_to_byte(source, self.start_point)
        end_byte = self._point_to_byte(source, self.end_point)
        if start_byte is not None and end_byte is not None:
            return source[start_byte:end_byte]
        return self.text
    
    @staticmethod
    def _point_to_byte(source: str, point: Tuple[int, int]) -> Optional[int]:
        """Convert (line, col) point to byte offset."""
        if not point:
            return None
        line, col = point
        lines = source.split('\n')
        if line >= len(lines):
            return None
        byte_offset = sum(len(l) + 1 for l in lines[:line])
        return byte_offset + col
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'type': self.node_type,
            'text': self.text,
            'line': self.line_number,
            'column': self.column,
            'children': [c.to_dict() for c in self.children],
        }


class ASTConverter:
    """Converts tree-sitter AST nodes to GenericASTNode format.
    
    Provides language-specific converters for extracting functions, classes,
    calls, imports, and other relevant code elements.
    """
    
    FUNCTION_NODE_TYPES = {
        'python': ['function_definition', 'async_function_definition'],
        'javascript': ['function_declaration', 'function', 'arrow_function', 
                      'method_definition', 'generator_function_declaration'],
        'typescript': ['function_declaration', 'function', 'arrow_function',
                       'method_definition', 'generator_function_declaration'],
        'go': ['function_declaration'],
        'rust': ['function_item'],
        'java': ['method_declaration', 'constructor_declaration'],
        'c': ['function_definition'],
        'cpp': ['function_definition', 'method_definition'],
    }
    
    CLASS_NODE_TYPES = {
        'python': ['class_definition'],
        'javascript': ['class_declaration', 'class'],
        'typescript': ['class_declaration', 'class', 'interface_declaration'],
        'go': ['type_declaration'],
        'rust': ['struct_item', 'impl_item'],
        'java': ['class_declaration', 'interface_declaration'],
    }
    
    CALL_NODE_TYPES = {
        'python': ['call'],
        'javascript': ['call_expression', 'new_expression'],
        'typescript': ['call_expression', 'new_expression'],
        'go': ['call_expression'],
        'rust': ['call_expression'],
        'java': ['method_invocation', 'class_instance_creation_expression'],
    }
    
    IMPORT_NODE_TYPES = {
        'python': ['import_statement', 'import_from_statement'],
        'javascript': ['import_statement', 'import_require'],
        'typescript': ['import_statement', 'import_require'],
        'go': ['import_declaration'],
        'rust': ['use_declaration', 'extern_crate_declaration'],
        'java': ['import_declaration'],
    }
    
    ASSIGNMENT_NODE_TYPES = {
        'python': ['assignment'],
        'javascript': ['variable_declaration', 'assignment_expression'],
        'typescript': ['variable_declaration', 'assignment_expression'],
    }
    
    def __init__(self, language: str):
        self.language = language
    
    def convert(self, node: Any) -> GenericASTNode:
        """Convert a tree-sitter node to GenericASTNode."""
        if node is None:
            return GenericASTNode(
                node_type='empty',
                text='',
                start_point=(0, 0),
                end_point=(0, 0)
            )
        
        children = []
        for child in node.children:
            child_node = self.convert(child)
            child_node.parent = None
            children.append(child_node)
        
        return GenericASTNode(
            node_type=node.type,
            text=node.text.decode('utf-8') if isinstance(node.text, bytes) else str(node.text),
            start_point=(node.start_point[0], node.start_point[1]),
            end_point=(node.end_point[0], node.end_point[1]),
            children=children,
            named=node.is_named
        )
    
    def extract_functions(self, root_node: Any, source: str) -> List[GenericASTNode]:
        """Extract all function definitions from AST."""
        functions = []
        func_types = self.FUNCTION_NODE_TYPES.get(self.language, ['function_definition'])
        
        def walk(node):
            if node.type in func_types:
                func_node = self._extract_function_info(node, source)
                if func_node:
                    functions.append(func_node)
            for child in node.children:
                walk(child)
        
        walk(root_node)
        return functions
    
    def _extract_function_info(self, node: Any, source: str) -> Optional[GenericASTNode]:
        """Extract detailed function information."""
        if node is None:
            return None
        
        func_name = self._get_function_name(node)
        if not func_name:
            return None
        
        return GenericASTNode(
            node_type='function',
            text=func_name,
            start_point=(node.start_point[0], node.start_point[1]),
            end_point=(node.end_point[0], node.end_point[1]),
            children=[]
        )
    
    def _get_function_name(self, node: Any) -> Optional[str]:
        """Get the name of a function from its definition node."""
        if node is None:
            return None
        
        if self.language == 'python':
            for child in node.children:
                if child.type == 'identifier':
                    return child.text.decode('utf-8') if isinstance(child.text, bytes) else str(child.text)
        
        elif self.language in ('javascript', 'typescript'):
            for child in node.children:
                if child.type == 'identifier':
                    return child.text.decode('utf-8') if isinstance(child.text, bytes) else str(child.text)
                if child.type == 'property_identifier':
                    return child.text.decode('utf-8') if isinstance(child.text, bytes) else str(child.text)
        
        elif self.language == 'go':
            for child in node.children:
                if child.type == 'identifier':
                    return child.text.decode('utf-8') if isinstance(child.text, bytes) else str(child.text)
        
        elif self.language == 'rust':
            for child in node.children:
                if child.type == 'identifier':
                    return child.text.decode('utf-8') if isinstance(child.text, bytes) else str(child.text)
        
        return None
    
    def extract_classes(self, root_node: Any, source: str) -> List[GenericASTNode]:
        """Extract all class definitions from AST."""
        classes = []
        class_types = self.CLASS_NODE_TYPES.get(self.language, ['class_definition'])
        
        def walk(node):
            if node.type in class_types:
                class_node = self._extract_class_info(node)
                if class_node:
                    classes.append(class_node)
            for child in node.children:
                walk(child)
        
        walk(root_node)
        return classes
    
    def _extract_class_info(self, node: Any) -> Optional[GenericASTNode]:
        """Extract class information."""
        if node is None:
            return None
        
        class_name = self._get_class_name(node)
        if not class_name:
            return None
        
        return GenericASTNode(
            node_type='class',
            text=class_name,
            start_point=(node.start_point[0], node.start_point[1]),
            end_point=(node.end_point[0], node.end_point[1]),
            children=[]
        )
    
    def _get_class_name(self, node: Any) -> Optional[str]:
        """Get the name of a class from its definition node."""
        if node is None:
            return None
        
        if self.language == 'python':
            for child in node.children:
                if child.type == 'identifier':
                    return child.text.decode('utf-8') if isinstance(child.text, bytes) else str(child.text)
        
        elif self.language in ('javascript', 'typescript'):
            for child in node.children:
                if child.type == 'identifier':
                    return child.text.decode('utf-8') if isinstance(child.text, bytes) else str(child.text)
                if child.type == 'type_identifier':
                    return child.text.decode('utf-8') if isinstance(child.text, bytes) else str(child.text)
        
        return None
    
    def extract_calls(self, root_node: Any, source: str) -> List[GenericASTNode]:
        """Extract all function/method calls from AST."""
        calls = []
        call_types = self.CALL_NODE_TYPES.get(self.language, ['call'])
        
        def walk(node):
            if node.type in call_types:
                call_node = self._extract_call_info(node)
                if call_node:
                    calls.append(call_node)
            for child in node.children:
                walk(child)
        
        walk(root_node)
        return calls
    
    def _extract_call_info(self, node: Any) -> Optional[GenericASTNode]:
        """Extract function call information."""
        if node is None:
            return None
        
        func_name = self._get_callee_name(node)
        
        return GenericASTNode(
            node_type='call',
            text=func_name or 'unknown',
            start_point=(node.start_point[0], node.start_point[1]),
            end_point=(node.end_point[0], node.end_point[1]),
            children=[]
        )
    
    def _get_callee_name(self, node: Any) -> Optional[str]:
        """Get the name of the function being called."""
        if node is None:
            return None
        
        if self.language == 'python':
            for child in node.children:
                if child.type == 'attribute':
                    return self._get_attribute_name(child)
                if child.type == 'identifier':
                    return child.text.decode('utf-8') if isinstance(child.text, bytes) else str(child.text)
        
        elif self.language in ('javascript', 'typescript'):
            for child in node.children:
                if child.type == 'identifier':
                    return child.text.decode('utf-8') if isinstance(child.text, bytes) else str(child.text)
                if child.type == 'property_identifier':
                    return child.text.decode('utf-8') if isinstance(child.text, bytes) else str(child.text)
                if child.type == 'member_expression':
                    return self._get_member_expression_name(child)
        
        return None
    
    def _get_attribute_name(self, node: Any) -> str:
        """Get attribute chain name (e.g., 'os.system')."""
        parts = []
        current = node
        while hasattr(current, 'type') and current.type == 'attribute':
            parts.append(current.children[1].text.decode('utf-8') if isinstance(current.children[1].text, bytes) else str(current.children[1].text))
            current = current.children[0]
        if hasattr(current, 'text'):
            parts.append(current.text.decode('utf-8') if isinstance(current.text, bytes) else str(current.text))
        return '.'.join(reversed(parts))
    
    def _get_member_expression_name(self, node: Any) -> str:
        """Get member expression name for JS/TS."""
        parts = []
        current = node
        while hasattr(current, 'type') and current.type == 'member_expression':
            if len(current.children) >= 2:
                prop = current.children[1]
                parts.append(prop.text.decode('utf-8') if isinstance(prop.text, bytes) else str(prop.text))
                current = current.children[0]
            else:
                break
        if hasattr(current, 'text'):
            parts.append(current.text.decode('utf-8') if isinstance(current.text, bytes) else str(current.text))
        return '.'.join(reversed(parts))
    
    def extract_imports(self, root_node: Any, source: str) -> List[GenericASTNode]:
        """Extract all import statements from AST."""
        imports = []
        import_types = self.IMPORT_NODE_TYPES.get(self.language, ['import'])
        
        def walk(node):
            if node.type in import_types:
                import_node = self._extract_import_info(node)
                if import_node:
                    imports.append(import_node)
            for child in node.children:
                walk(child)
        
        walk(root_node)
        return imports
    
    def _extract_import_info(self, node: Any) -> Optional[GenericASTNode]:
        """Extract import information."""
        if node is None:
            return None
        
        import_text = self._get_import_text(node)
        
        return GenericASTNode(
            node_type='import',
            text=import_text or 'unknown',
            start_point=(node.start_point[0], node.start_point[1]),
            end_point=(node.end_point[0], node.end_point[1]),
            children=[]
        )
    
    def _get_import_text(self, node: Any) -> Optional[str]:
        """Get the module being imported."""
        if node is None:
            return None
        
        if self.language == 'python':
            for child in node.children:
                if child.type == 'dotted_name':
                    return child.text.decode('utf-8') if isinstance(child.text, bytes) else str(child.text)
                if child.type == 'module':
                    return child.text.decode('utf-8') if isinstance(child.text, bytes) else str(child.text)
        
        elif self.language in ('javascript', 'typescript'):
            for child in node.children:
                if child.type == 'string':
                    text = child.text.decode('utf-8') if isinstance(child.text, bytes) else str(child.text)
                    return text.strip('"\'')
        
        return None
    
    def extract_assignments(self, root_node: Any, source: str) -> List[GenericASTNode]:
        """Extract all variable assignments from AST."""
        assignments = []
        assign_types = self.ASSIGNMENT_NODE_TYPES.get(self.language, ['assignment'])
        
        def walk(node):
            if node.type in assign_types:
                assign_node = self._extract_assignment_info(node)
                if assign_node:
                    assignments.append(assign_node)
            for child in node.children:
                walk(child)
        
        walk(root_node)
        return assignments
    
    def _extract_assignment_info(self, node: Any) -> Optional[GenericASTNode]:
        """Extract assignment information."""
        if node is None:
            return None
        
        var_name = self._get_variable_name(node)
        
        return GenericASTNode(
            node_type='assignment',
            text=var_name or 'unknown',
            start_point=(node.start_point[0], node.start_point[1]),
            end_point=(node.end_point[0], node.end_point[1]),
            children=[]
        )
    
    def _get_variable_name(self, node: Any) -> Optional[str]:
        """Get the variable being assigned to."""
        if node is None:
            return None
        
        if self.language == 'python':
            for child in node.children:
                if child.type == 'identifier':
                    return child.text.decode('utf-8') if isinstance(child.text, bytes) else str(child.text)
        
        elif self.language in ('javascript', 'typescript'):
            for child in node.children:
                if child.type == 'identifier':
                    return child.text.decode('utf-8') if isinstance(child.text, bytes) else str(child.text)
                if child.type == 'variable_declarator':
                    for subchild in child.children:
                        if subchild.type == 'identifier':
                            return subchild.text.decode('utf-8') if isinstance(subchild.text, bytes) else str(subchild.text)
        
        return None
