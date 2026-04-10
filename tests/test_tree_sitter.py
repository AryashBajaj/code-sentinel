import warnings
import pytest
from src.analyzer.tree_sitter import parser, language_detector, ast_converter


class TestLanguageDetector:
    def test_detect_python(self):
        detector = language_detector.LanguageDetector()
        assert detector.detect_from_path("test.py") == "python"
        assert detector.detect_from_path("test.pyw") == "python"
        assert detector.detect_from_path("module.py") == "python"
    
    def test_detect_javascript(self):
        detector = language_detector.LanguageDetector()
        assert detector.detect_from_path("app.js") == "javascript"
        assert detector.detect_from_path("index.jsx") == "javascript"
        assert detector.detect_from_path("module.js") == "javascript"
    
    def test_detect_typescript(self):
        detector = language_detector.LanguageDetector()
        assert detector.detect_from_path("app.ts") == "typescript"
        assert detector.detect_from_path("app.tsx") == "typescript"
        assert detector.detect_from_path("types.ts") == "typescript"
    
    def test_detect_unsupported(self):
        detector = language_detector.LanguageDetector()
        assert detector.detect_from_path("test.txt") is None
        assert detector.detect_from_path("Makefile") is None
    
    def test_detect_from_content_python(self):
        detector = language_detector.LanguageDetector()
        content = "def foo():\n    pass\nimport os"
        assert detector.detect_language("file.txt", content) == "python"
    
    def test_detect_from_content_javascript(self):
        detector = language_detector.LanguageDetector()
        content = "function foo() { } const x = 1"
        assert detector.detect_language("file.txt", content) == "javascript"


class TestASTConverter:
    def test_convert_python_function(self):
        warnings.filterwarnings("ignore")
        import tree_sitter_languages
        
        converter = ast_converter.ASTConverter("python")
        code = "def hello(): pass"
        tree = tree_sitter_languages.get_parser("python").parse(bytes(code, "utf-8"))
        
        root = converter.convert(tree.root_node)
        assert root.node_type == "module"
        
        functions = converter.extract_functions(tree.root_node, code)
        assert len(functions) == 1
        assert functions[0].text == "hello"
    
    def test_convert_python_class(self):
        warnings.filterwarnings("ignore")
        import tree_sitter_languages
        
        converter = ast_converter.ASTConverter("python")
        code = "class Foo: pass"
        tree = tree_sitter_languages.get_parser("python").parse(bytes(code, "utf-8"))
        
        classes = converter.extract_classes(tree.root_node, code)
        assert len(classes) == 1
        assert classes[0].text == "Foo"
    
    def test_convert_python_call(self):
        warnings.filterwarnings("ignore")
        import tree_sitter_languages
        
        converter = ast_converter.ASTConverter("python")
        code = "foo()"
        tree = tree_sitter_languages.get_parser("python").parse(bytes(code, "utf-8"))
        
        calls = converter.extract_calls(tree.root_node, code)
        assert len(calls) == 1
        assert calls[0].text == "foo"
    
    def test_convert_python_import(self):
        warnings.filterwarnings("ignore")
        import tree_sitter_languages
        
        converter = ast_converter.ASTConverter("python")
        code = "import os"
        tree = tree_sitter_languages.get_parser("python").parse(bytes(code, "utf-8"))
        
        imports = converter.extract_imports(tree.root_node, code)
        assert len(imports) == 1
        assert "os" in imports[0].text
    
    def test_convert_javascript_function(self):
        warnings.filterwarnings("ignore")
        import tree_sitter_languages
        
        converter = ast_converter.ASTConverter("javascript")
        code = "function hello() { }"
        tree = tree_sitter_languages.get_parser("javascript").parse(bytes(code, "utf-8"))
        
        functions = converter.extract_functions(tree.root_node, code)
        assert len(functions) == 1
        assert functions[0].text == "hello"
    
    def test_convert_javascript_method_definition(self):
        warnings.filterwarnings("ignore")
        import tree_sitter_languages
        
        converter = ast_converter.ASTConverter("javascript")
        code = "class Foo { bar() { } }"
        tree = tree_sitter_languages.get_parser("javascript").parse(bytes(code, "utf-8"))
        
        functions = converter.extract_functions(tree.root_node, code)
        assert len(functions) == 1
        assert functions[0].text == "bar"


class TestTreeSitterParser:
    def test_parse_python(self):
        warnings.filterwarnings("ignore")
        p = parser.TreeSitterParser()
        code = "def hello(): return 42"
        result = p.parse(code, "python", "test.py")
        
        assert result is not None
        assert result.language == "python"
        assert result.root_node is not None
        assert len(result.functions) == 1
    
    def test_parse_javascript(self):
        warnings.filterwarnings("ignore")
        p = parser.TreeSitterParser()
        code = "function hello() { return 42; }"
        result = p.parse(code, "javascript", "test.js")
        
        assert result is not None
        assert result.language == "javascript"
        assert len(result.functions) == 1
    
    def test_parse_unsupported_language(self):
        warnings.filterwarnings("ignore")
        p = parser.TreeSitterParser()
        code = "some unknown language code"
        result = p.parse(code, "unsupported_lang", "test.xyz")
        
        assert result is None
    
    def test_parse_directory(self, tmp_path):
        warnings.filterwarnings("ignore")
        test_file = tmp_path / "test.py"
        test_file.write_text("def foo(): pass\n")
        
        p = parser.TreeSitterParser()
        results = p.parse_directory(str(tmp_path))
        
        assert len(results) == 1
        assert results[0].language == "python"
        assert len(results[0].functions) == 1
    
    def test_parse_directory_with_extensions(self, tmp_path):
        warnings.filterwarnings("ignore")
        py_file = tmp_path / "test.py"
        py_file.write_text("def foo(): pass\n")
        js_file = tmp_path / "test.js"
        js_file.write_text("function bar() { }\n")
        
        p = parser.TreeSitterParser()
        results = p.parse_directory(str(tmp_path), extensions={".py"})
        
        assert len(results) == 1
        assert results[0].language == "python"
    
    def test_parse_empty_code(self):
        warnings.filterwarnings("ignore")
        p = parser.TreeSitterParser()
        result = p.parse("", "python", "empty.py")
        
        assert result is not None
        assert result.root_node is not None
    
    def test_parse_multifile_project(self, tmp_path):
        warnings.filterwarnings("ignore")
        main_py = tmp_path / "main.py"
        main_py.write_text("from utils import helper\n\ndef main():\n    helper()\n")
        
        utils_py = tmp_path / "utils.py"
        utils_py.write_text("def helper(): pass\n")
        
        p = parser.TreeSitterParser()
        results = p.parse_directory(str(tmp_path))
        
        assert len(results) == 2
        languages = {r.language for r in results}
        assert languages == {"python"}
    
    def test_get_supported_languages(self):
        p = parser.TreeSitterParser()
        langs = p.get_supported_languages()
        
        assert "python" in langs
        assert "javascript" in langs
        assert "typescript" in langs


class TestGenericASTNode:
    def test_line_number(self):
        warnings.filterwarnings("ignore")
        node = ast_converter.GenericASTNode(
            node_type="test",
            text="test",
            start_point=(5, 10),
            end_point=(5, 14)
        )
        assert node.line_number == 6
    
    def test_column(self):
        warnings.filterwarnings("ignore")
        node = ast_converter.GenericASTNode(
            node_type="test",
            text="test",
            start_point=(5, 10),
            end_point=(5, 14)
        )
        assert node.column == 11
    
    def test_get_child(self):
        warnings.filterwarnings("ignore")
        child = ast_converter.GenericASTNode(
            node_type="identifier",
            text="foo",
            start_point=(0, 0),
            end_point=(0, 3)
        )
        parent = ast_converter.GenericASTNode(
            node_type="function",
            text="",
            start_point=(0, 0),
            end_point=(0, 10),
            children=[child]
        )
        
        assert parent.get_child("identifier") == child
        assert parent.get_child("nonexistent") is None
    
    def test_to_dict(self):
        warnings.filterwarnings("ignore")
        node = ast_converter.GenericASTNode(
            node_type="test",
            text="test text",
            start_point=(0, 0),
            end_point=(0, 9),
            children=[]
        )
        
        d = node.to_dict()
        assert d["type"] == "test"
        assert d["text"] == "test text"
        assert d["line"] == 1
        assert d["column"] == 1
