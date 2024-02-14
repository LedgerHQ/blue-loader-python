Scripts
=======

The Python loader includes a collection of useful scripts for managing BOLOS
devices. This section includes an overview of some of the most important scripts
and how they can be used.

In order to use any of these scripts, the device must be in the dashboard
application (no apps are open, the device should display a list of installed
apps).

Here is an example using the :ref:`deleteApp.py` script from the command-line:

.. code-block:: bash

   python -m ledgerblue.deleteApp --targetId 0x31100002 --appName "Hello World"

The above command will delete the app named "Hello World" from the connected
Leger Nano S.

See the :doc:`script_reference` for the detailed documentation about each
script.
