from PyInstaller.utils.hooks import collect_data_files, collect_submodules

# Collect all PyQt5 submodules
hiddenimports = collect_submodules('PyQt5')

# Collect all PyQt5 data files
datas = collect_data_files('PyQt5')

# Add Qt plugins
from PyQt5 import QtCore
import os

# Get the Qt plugins path
pyqt_path = os.path.dirname(QtCore.__file__)
qt_plugins_path = os.path.join(pyqt_path, 'Qt5', 'plugins')

# Add platform plugins
platforms_dir = os.path.join(qt_plugins_path, 'platforms')
if os.path.exists(platforms_dir):
    datas.append((platforms_dir, 'Qt5/plugins/platforms'))

# Add style plugins
styles_dir = os.path.join(qt_plugins_path, 'styles')
if os.path.exists(styles_dir):
    datas.append((styles_dir, 'Qt5/plugins/styles')) 
