from setuptools import setup, find_packages


with open('README.txt') as f:
    long_description = ''.join(f.readlines())


setup(
    name='ghia_nymsapet',
    version='0.1',
    description='GitHub issue assigned',
    long_description=long_description,
    author='Petr Nymsa',
    author_email='ondrej@caletka.cz',
    keywords='github, issue, assign',
    license='MIT',
    url='https://github.com/mi-pyt-ghia/petrnymsa',
    packages=find_packages(),
    classifiers=[
        'Intended Audience :: Developers',
        'License :: Public Domain',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Software Development :: Libraries',
    ],
    entry_points={
        'console_scripts': [
            'ghia = ghia.cli:run',
        ],
    },
    install_requires=['Flask', 'click>=6', 'requests'],
    zip_safe=False,
)
