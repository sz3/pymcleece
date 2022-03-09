from glob import iglob
from os import makedirs
from os.path import join as path_join, abspath, dirname, basename, isdir
from shutil import copyfile


def main():
    # copy over the built library for local dev
    builddir = path_join(dirname(abspath(__file__)), 'build')
    localdir = path_join(dirname(abspath(__file__)), 'mcleece')
    for f in iglob(f'{builddir}/**/libmcleece*', recursive=True):
        if isdir(f):
            continue
        print(f'copying {f}')
        copyfile(f, path_join(localdir, basename(f)))


if __name__ == '__main__':
    main()
