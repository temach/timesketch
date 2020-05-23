# -*- coding: utf-8 -*-
"""A plugin that reveals encrypted files on the filessystem."""

from __future__ import unicode_literals

import re

import requests

from plaso.analysis import interface
from plaso.analysis import logger
from plaso.analysis import manager
from plaso.containers import reports
import subprocess

class TchuntngPlugin(interface.AnalysisPlugin):
  """Find encrypted files, requires TCHunt-ng installed."""

  NAME = 'tchuntng'

  # Indicate that we can run this plugin during regular extraction.
  ENABLE_IN_EXTRACTION = True

  _SUPPORTED_EVENT_DATA_TYPES = frozenset([
      'fs:stat'])

  def __init__(self):
    """Initializes the TCHunt-ng analysis plugin."""
    super(TchuntngPlugin, self).__init__()

    self._cache = {}
    self._results = {}

  def CompileReport(self, mediator):
    """Compiles an analysis report.

    Args:
      mediator (AnalysisMediator): mediates interactions between analysis
          plugins and other components, such as storage and dfvfs.

    Returns:
      AnalysisReport: analysis report.
    """
    lines_of_text = []
    for user, filepaths in sorted(self._results.items()):
      lines_of_text.append(' == USER: {0:s} =='.format(user))
      for path in sorted(filepaths):
        lines_of_text.append('  {}'.format(path))
      lines_of_text.append('')

    lines_of_text.append('')
    report_text = '\n'.join(lines_of_text)
    analysis_report = reports.AnalysisReport(plugin_name=self.NAME, text=report_text)
    analysis_report.report_dict = self._results
    return analysis_report

  # pylint: disable=unused-argument
  def ExamineEvent(self, mediator, event, event_data):
    """Analyzes an event.

    Args:
      mediator (AnalysisMediator): mediates interactions between analysis
          plugins and other components, such as storage and dfvfs.
      event (EventObject): event to examine.
      event_data (EventData): event data.
    """
    if event_data.data_type not in self._SUPPORTED_EVENT_DATA_TYPES:
      return

    filename = getattr(event_data, 'filename', None)
    if not filename:
      return
    
    if filename in self._cache:
      return
    else:
      self._cache[filename] = True

    user = mediator.GetUsernameForPath(filename)

    # We still want this information in here, so that we can
    # manually deduce the username.
    if not user:
      user = "Not found"

    completed = subprocess.run("tchuntng {}".format(filename), shell=True)
    if completed.returncode == 0:
      # this is encrypted
      self._results.setdefault(user, [])
      if filename not in self._results[user]:
        self._results[user].append(filename)

manager.AnalysisPluginManager.RegisterPlugin(TchuntngPlugin)
