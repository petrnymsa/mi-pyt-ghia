from setuptools import setup, find_packages


with open('README') as f:
    long_description = ''.join(f.readlines())


setup(
    name='ghia_nymsapet',
    version='0.3.0',
    description='GitHub issue assigner',
    long_description=long_description,
    author='Petr Nymsa',
    author_email='nymsapet@fit.cvut.cz',
    keywords='github, issue, assign',
    license='MIT',
    url='https://github.com/mi-pyt-ghia/petrnymsa',
    packages=find_packages(),
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Framework :: Flask',
        'Environment :: Console',
        'Environment :: Web Environment',
        'Topic :: Software Development :: Libraries',
    ],
    entry_points={
        'console_scripts': [
            'ghia = ghia.cli:run',
        ],
    },
    install_requires=['Flask', 'click>=6', 'requests'],
    include_package_data=True,
    zip_safe=False,
)
