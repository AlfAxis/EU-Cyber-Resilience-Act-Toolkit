"""Exception types shared across the toolkit."""

from __future__ import annotations


class ToolkitError(Exception):
    """An expected, user-facing failure.

    The message is already localised and safe to print as-is; the CLI turns it
    into a one-line error and exit code 2 instead of a traceback.
    """


class VulnSourceError(ToolkitError):
    """The vulnerability data source could not be reached or returned garbage."""
