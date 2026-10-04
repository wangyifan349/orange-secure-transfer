from pathlib import Path

from Cython.Build import cythonize
from setuptools import Extension, setup


PROJECT_DIR = Path(__file__).resolve().parent
MODULE_NAME = "secure_transfer_gui_cn"
SOURCE_FILE = PROJECT_DIR / f"{MODULE_NAME}.py"


if not SOURCE_FILE.is_file():
    raise FileNotFoundError(f"Source file not found: {SOURCE_FILE}")


setup(
    name=f"{MODULE_NAME}_compiled",
    ext_modules=cythonize(
        [Extension(MODULE_NAME, [str(SOURCE_FILE)])],
        # Keep normal Python method binding semantics for PyQt callbacks.
        compiler_directives={"language_level": "3", "binding": True},
        annotate=False,
    ),
)


#python setup.py build_ext --inplace
