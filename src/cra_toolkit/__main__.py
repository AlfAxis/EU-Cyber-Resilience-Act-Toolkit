"""Allow ``python -m cra_toolkit``."""

import sys

from cra_toolkit.cli import main

if __name__ == "__main__":
    sys.exit(main())
