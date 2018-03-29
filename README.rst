===========
bits_parser
===========


Extract BITS jobs from QMGR queue and store them as pipe-delimited records.

This is forked from `ANSSI bits_parser <https://github.com/ANSSI-FR/bits_parser>`_ to refactor as a simple Python 2.7
script.


Usage
=====

QMGR queues are usually *.dat* files located in the folder
``%%ALLUSERSPROFILE%%\Microsoft\Network\Downloader`` on a Windows system.

Once those files have been located (*e.g.* ``qmgr0.dat`` and ``qmgr1.dat``) you
can run `bits_jobs_parser.py` by issuing the following command passing the directory
containing the files:

  .. code:: bash

    python bits_jobs_parser.py C:\ProgramData\Microsoft\Network\Downloader\



Related works
=============

`Finding your naughty BITS <https://www.dfrws.org/sites/default/files/session-files/pres-finding_your_naughty_bits.pdf>`_ [DFRWS USA 2015, Matthew Geiger]

`BITSInject <https://github.com/SafeBreach-Labs/BITSInject>`_ [DEFCON 2017, Dor Azouri]

`ANSSI bits_parser <https://github.com/ANSSI-FR/bits_parser>`_ [Project forked]