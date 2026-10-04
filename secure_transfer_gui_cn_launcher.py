"""PyInstaller entry point for the compiled GUI extension.

Build (run these commands in this directory):

    python setup.py build_ext --inplace
    pyinstaller --clean -F -n secure_transfer_gui_cn secure_transfer_gui_cn_launcher.py

The result is dist\\secure_transfer_gui_cn.exe. Add -w to hide the console;
without it you also see the connection and handshake print logs.
"""

import secure_transfer_gui_cn


if __name__ == "__main__":
    raise SystemExit(secure_transfer_gui_cn.main())
