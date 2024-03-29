import os
import re
import sys
import platform
import subprocess
from os.path import join as path_join, abspath, dirname

from setuptools import setup, Extension, find_packages
from setuptools.command.build_ext import build_ext

try:
    from packaging.version import Version
except:
    from distutils.version import LooseVersion as Version


class CMakeExtension(Extension):
    def __init__(self, name, sourcedir=''):
        Extension.__init__(self, name, sources=[])
        self.sourcedir = os.path.abspath(sourcedir)


class CMakeBuild(build_ext):
    def run(self):
        try:
            out = subprocess.check_output(['cmake', '--version'])
        except OSError:
            raise RuntimeError("CMake must be installed to build the following extensions: " +
                               ", ".join(e.name for e in self.extensions))

        cmake_version = Version(re.search(r'version\s*([\d.]+)', out.decode()).group(1))
        if cmake_version < Version('3.5.0'):
            raise RuntimeError("CMake >= 3.5.0 is required")

        for ext in self.extensions:
            self.build_extension(ext)

    def build_extension(self, ext):
        extdir = path_join(abspath(dirname(self.get_ext_fullpath(ext.name))), 'mcleece')
        print('extdir is {}'.format(extdir))
        cmake_args = ['-DBUILD_LIBSODIUM=1']
        cmake_args += ['-DCMAKE_LIBRARY_OUTPUT_DIRECTORY=' + extdir]

        build_type = os.environ.get("BUILD_TYPE", "Release")
        build_args = ['--config', build_type]

        # Pile all .so in one place and use $ORIGIN as RPATH
        cmake_args += ["-DCMAKE_BUILD_WITH_INSTALL_RPATH=TRUE"]
        cmake_args += ["-DCMAKE_INSTALL_RPATH={}".format("$ORIGIN")]

        if platform.system() == "Windows":
            cmake_args += ['-DCMAKE_LIBRARY_OUTPUT_DIRECTORY_{}={}'.format(build_type.upper(), extdir)]
            if sys.maxsize > 2**32:
                cmake_args += ['-A', 'x64']
            build_args += ['--', '/m']
        else:
            cmake_args += ['-DCMAKE_BUILD_TYPE=' + build_type]
            build_args += ['--', '-j4']

        env = os.environ.copy()
        env['CXXFLAGS'] = '{} -DVERSION_INFO=\\"{}\\"'.format(env.get('CXXFLAGS', ''),
                                                              self.distribution.get_version())
        os.makedirs(self.build_temp, exist_ok=True)
        print(f'build dir {self.build_temp}, srcdir {ext.sourcedir}')
        subprocess.check_call(['cmake', ext.sourcedir] + cmake_args, cwd=self.build_temp, env=env)
        subprocess.check_call(['cmake',
                               '--build', '.',
                               '--target', 'mcleece',
                               ] + build_args,
                              cwd=self.build_temp)


def read_version():
    return '0.4.0'  # pull version from libmcleece, eventually


setup(
    name='mcleece',
    license='MIT',
    url="https://github.com/sz3/pymcleece",
    version=read_version(),

    author='Stephen Zimmerman',
    author_email='sz@recv.cc',
    description='Python wrapper for libmcleece encryption library',
    long_description=open("README.md").read(),
    long_description_content_type='text/markdown',

    ext_modules=[CMakeExtension('libmcleece', 'libmcleece')],
    packages=find_packages(exclude=["tests"]),
    cmdclass=dict(build_ext=CMakeBuild),
    zip_safe=False,
    classifiers=[
        'License :: OSI Approved :: MIT License',
    ],

    install_requires=[
        'PyNaCl>=1.3.0',
    ],
)
