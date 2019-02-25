import h2.connection
from ngh2._connection import H2Connection

h2.connection.H2Connection = H2Connection

from ngh2._version import __version__