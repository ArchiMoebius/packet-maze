import site
import sys
import setuptools


print(f"{setuptools.__version__} ENABLE_USER_SITE={site.ENABLE_USER_SITE!r} no_user_site={sys.flags.no_user_site!r}")


setuptools.setup()
