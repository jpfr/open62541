import setuptools
from Cython.Build import cythonize

open62541_extension = setuptools.Extension(
    "open62541_ext",
    language='c',
    sources=['open62541.pyx'],
    libraries=['open62541']
)

setuptools.setup(
    name="open62541",
    ext_modules=cythonize(
        open62541_extension,
        language_level=3.6,
        compiler_directives={"linetrace": True} # Opt-in via CYTHON_TRACE macro
    ),
    include_dirs=["open62541"],
    libraries=["open62541"],
)
