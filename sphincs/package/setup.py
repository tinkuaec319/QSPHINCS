# setup.py
from setuptools import setup
from Cython.Build import cythonize

setup(
    ext_modules=cythonize(["gbs_hash.py", "sphincs.py"], compiler_directives={'language_level': "3"})
)