"""*pego: parsing for the average programmer*

PEGO is designed to make parsing accessible
to the average programmer with no previous experience.

At the same time, a VM based architecture does
not limit performance to the speed of generated
python code.
"""

from setuptools import setup


__author__ = 'Kurt Rose'
__version__ = '0.1dev'
__contact__ = 'kurt@kurtrose.com'
__url__ = 'https://github.com/kurtbrose/pego'
__license__ = 'BSD'


setup(
	name='pego',
	version=__version__,
	description='Easy-to-use Parsing library',
	long_description=__doc__,
	author=__author__,
	author_email=__contact__,
	url=__url__,
	packages=['pego'],
	install_requires=[],
	extras_require={},
	license=__license__,
	platforms='any',
	classifiers=[
		'Intended Audience :: Developers',
		'Programming Language :: Python :: 2.7',
		'Programming Language :: Python :: 3.6']
)
