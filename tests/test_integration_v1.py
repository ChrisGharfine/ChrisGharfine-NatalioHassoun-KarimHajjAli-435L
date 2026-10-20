"""Explicit entry point; importing this file never modifies a database."""
if __name__ == "__main__":
    import runpy
    from pathlib import Path
    runpy.run_path(str(Path(__file__).with_name("owned_integration.py")), run_name="__main__")
