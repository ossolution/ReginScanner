#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Regin Scanner
#
# Detection is based on three detection methods:
#
# 1. File Name IOC 
#    Based on the reports published by Symantec and Kaspersky
#
# 2. Yara Ruleset
#    Based on my rules published on pastebin:
#    http://pastebin.com/0ZEWvjsC
#
# 3. Hash Check
#    Compares known malicious SHA256 hashes with scanned files
#
# 4. File System Scanner for Regin Virtual Filesystems
#    based on .evt virtual filesystem detection by Paul Rascagneres, G DATA
#    Reference: https://blog.gdatasoftware.com/uploads/media/regin-detect.py
#
# If you like ReginScanner you'll love THOR our full-featured APT Scanner
# 
# Ramin Najjarbashi
# POS CO
# December 2014
# v0.1b
# 
# DISCLAIMER - USE AT YOUR OWN RISK.

import re
import getopt
import sys
import time
import os
import scandir
import traceback
import binascii
import yara
import hashlib
from PyQt4 import QtGui,QtCore
from gui import *
from PyQt4.Qt import QFileDialog
import ctypes

if sys.platform == "linux" or sys.platform == "linux2":
    # linux
	pass
elif sys.platform == "darwin":
    # OS X
	pass
elif sys.platform == "win32":
	myappid = 'POS.ReginScanner.AntiVirus.1' # arbitrary string
	ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)

EVIL_FILES = [
    '\\usbclass.sys',
    '\\adpu160.sys',
    '\\msrdc64.dat',
    '\\msdcsvc.dat',
    '\\config\\SystemAudit.Evt',
    '\\config\\SecurityAudit.Evt',
    '\\config\\SystemLog.evt',
    '\\config\\ApplicationLog.evt',
    '\\ime\\imesc5\\dicts\\pintlgbs.imd',
    '\\ime\\imesc5\\dicts\\pintlgbp.imd',
    'ystem32\\winhttpc.dll',
    'ystem32\\wshnetc.dll',
    '\\SysWow64\\wshnetc.dll',
    'ystem32\\svcstat.exe',
    'ystem32\\svcsstat.exe',
    'IME\\IMESC5\\DICTS\\PINTLGBP.IMD',
    'ystem32\\wsharp.dll',
    'ystem32\\wshnetc.dll',
    'pchealth\\helpctr\\Database\\cdata.dat',
    'pchealth\\helpctr\\Database\\cdata.edb',
    'Windows\\Panther\\setup.etl.000',
    'ystem32\\wbem\\repository\\INDEX2.DATA',
    'ystem32\\wbem\\repository\\OBJECTS2.DATA',
    'ystem32\\dnscache.dat',
    'ystem32\\mregnx.dat',
    'ystem32\\displn32.dat',
    'ystem32\\dmdskwk.dat',
    'ystem32\\nvwrsnu.dat',
    'ystem32\\tapiscfg.dat',
    'ystem32\\pciclass.sys'
]

EVIL_HASHES = [
    '20831e820af5f41353b5afab659f2ad42ec6df5d9692448872f3ed8bbb40ab92',
    '225e9596de85ca7b1025d6e444f6a01aa6507feef213f4d2e20da9e7d5d8e430',
    '392f32241cd3448c7a435935f2ff0d2cdc609dda81dd4946b1c977d25134e96e',
    '40c46bcab9acc0d6d235491c01a66d4c6f35d884c19c6f410901af6d1e33513b',
    '4139149552b0322f2c5c993abccc0f0d1b38db4476189a9f9901ac0d57a656be',
    '4e39bc95e35323ab586d740725a1c8cbcde01fe453f7c4cac7cced9a26e42cc9',
    '5001793790939009355ba841610412e0f8d60ef5461f2ea272ccf4fd4c83b823',
    '5c81cf8262f9a8b0e100d2a220f7119e54edfc10c4fb906ab7848a015cd12d90',
    '7553d4a5914af58b23a9e0ce6a262cd230ed8bb2c30da3d42d26b295f9144ab7',
    '7d38eb24cf5644e090e45d5efa923aff0e69a600fb0ab627e8929bb485243926',
    '8098938987e2f29e3ee416b71b932651f6430d15d885f2e1056d41163ae57c13',
    '8389b0d3fb28a5f525742ca2bf80a81cf264c806f99ef684052439d6856bc7e7',
    '8d7be9ed64811ea7986d788a75cbc4ca166702c6ff68c33873270d7c6597f5db',
    '9cd5127ef31da0e8a4e36292f2af5a9ec1de3b294da367d7c05786fe2d5de44f',
    '9ddbe7e77cb5616025b92814d68adfc9c3e076dddbe29de6eb73701a172c3379',
    'a0d82c3730bc41e267711480c8009883d1412b68977ab175421eabc34e4ef355',
    'a0e3c52a2c99c39b70155a9115a6c74ea79f8a68111190faa45a8fd1e50f8880',
    'a6603f27c42648a857b8a1cbf301ed4f0877be75627f6bbe99c0bfd9dc4adb35',
    'a7493fac96345a989b1a03772444075754a2ef11daa22a7600466adc1f69a669',
    'a7e3ad8ea7edf1ca10b0e5b0d976675c3016e5933219f97e94900dea0d470abe',
    'a7e3ad8ea7edf1ca10b0e5b0d976675c3016e5933219f97e94900dea0d470abe',
    'b12c7d57507286bbbe36d7acf9b34c22c96606ffd904e3c23008399a4a50c047',
    'b755ed82c908d92043d4ec3723611c6c5a7c162e78ac8065eb77993447368fce',
    'c0cf8e008fbfa0cb2c61d968057b4a077d62f64d7320769982d28107db370513',
    'cca1850725f278587845cd19cbdf3dceb6f65790d11df950f17c5ff6beb18601',
    'df77132b5c192bd8d2d26b1ebb19853cf03b01d38afd5d382ce77e0d7219c18c',
    'e1ba03a10a40aab909b2ba58dcdfd378b4d264f1f4a554b669797bbb8c8ac902',
    'e420d0cf7a7983f78f5a15e6cb460e93c7603683ae6c41b27bf7f2fa34b2d935',
    'ecd7de3387b64b7dab9a7fb52e8aa65cb7ec9193f8eac6a7d79407a6a932ef69',
    'f1d903251db466d35533c28e3c032b7212aa43c8d64ddf8c5521b43031e69e1e',
    'f89549fc84a8d0f8617841c6aa4bb1678ea2b6081c1f7f74ab1aebd4db4176e4',
    'fd92fd7d0f925ccc0b4cbb6b402e8b99b64fa6a4636d985d78e5507bd4cfecef',
    'fe1419e9dde6d479bd7cda27edd39fafdab2668d498931931a2769b370727129',
]

class frmMain(QtGui.QMainWindow):
    def __init__(self, parent=None):
        QtGui.QWidget.__init__(self, parent)
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.center()
        self.ui.RunScanner.clicked[bool].connect(self.run_scanner)
        self.ui.scan_progressBar.setMinimum(0)
        self.ui.scan_progressBar.setMaximum(100)
        #self.ui.Pos_logo.mousePressEvent.connect(open_pos)
       
    def run_scanner(self, pressed):
        # Startup
        self.ui.scan_progressBar.setValue(0)
        scan_path = str(QFileDialog.getExistingDirectory(self, u"انتخاب پوشه برای اسکن"))
        self.ui.checkedFiles.clear()
        self.ui.checkedFiles.append(u'<font color=blue>شروع…</font>')
        if 'WINDIR' in os.environ and scan_path == '':
            scan_path = os.environ['WINDIR']
        elif scan_path == '':
            self.WarningEvent(u'پوشه‌ای برای اسکن انتخاب نشده',u'اخطار')
            return

        # Compromised marker
        compromised = False
        c = 0

        # Compiling yara rules
        if os.path.exists('regin_rules.yar'):
            self.ui.checkedFiles.append(u'<font color=green>آماه سازی …</font>')
            self.ui.checkedFiles.append(u'<font color=green>ممکن است عملیات کمی زمانبر باشد... صبور باشید</font>')
            QtGui.QApplication.processEvents()

            rules = yara.compile('regin_rules.yar')
        else: 
            self.WarningEvent(u'فایل مربوط به مشخصات بدافزار یافت نشد',u'اخطار')
            return
        
        QtGui.QApplication.processEvents()
        x = value = 0
        for root, dirs, files in os.walk(scan_path):
            for f in files:
                x = x+1
        x = 100.0/x

        for root, directories, files in scandir.walk(scan_path, onerror=walkError, followlinks=False):
                # Loop through files
            for filename in files:
                try:

                    # Get the file and path
                    filePath = os.path.join(root,filename)

                    # Counter
                    c += 1

                    self.ui.checkedFiles.append(u"[اسکن فایلِ] %s" % filePath.decode('utf-8'))
                    QtGui.QApplication.processEvents()

                    file_size = 0
                    try:
                        file_size = os.stat(filePath).st_size
                    except:
                        pass

                    # File Name Checks -------------------------------------------------
                    for file in EVIL_FILES:
                        if file in filePath:
                            # print  "\bREGIN File Name MATCH: %s" % filePath
                            compromised = True

                    # Yara Check -------------------------------------------------------
                    if 'rules' in locals():
                        if file_size < 500000:
                            try:
                                matches = rules.match(filePath)
                                if matches:
                                    for match in matches:
                                        # print  "\bREGIN Yara Rule MATCH: %s FILE: %s" % ( match, filePath)
                                        compromised = True
                            except Exception, e:
                                print e

                    # Hash Check -------------------------------------------------------
                    if file_size < 500000:
                        if sha256(filePath) in EVIL_HASHES:
                            # print  "\bREGIN SHA256 Hash MATCH: %s FILE: %s" % ( sha256(filePath), filePath)
                            compromised = True

                    # CRC Check --------------------------------------------------------
                    try:
                        if file_size <= 11:
                            continue

                        # Code from Paul Rascagneres
                        fp = open(filePath, 'r')
                        SectorSize=fp.read(2)[::-1]
                        MaxSectorCount=fp.read(2)[::-1]
                        MaxFileCount=fp.read(2)[::-1]
                        FileTagLength=fp.read(1)[::-1]
                        CRC32custom=fp.read(4)[::-1]
                        fp.close()

                        fp = open(filePath, 'r')
                        data=fp.read(0x7)
                        crc = binascii.crc32(data, 0x45)
                        crc2 = '%08x' % (crc & 0xffffffff)


                        if CRC32custom.encode('hex') == crc2:
                            # print  "\bREGIN Virtual Filesystem MATCH: %s" % filePath
                            compromised = True

                    except Exception, e:
                        print e

                except Exception, e:
                    print e

                else:
                    value +=  x
                    self.ui.scan_progressBar.setValue(value)
                    QtGui.QApplication.processEvents()

        self.ui.scan_progressBar.setValue(100)
        if compromised:
            self.ErrorEvent(u'فایلی مطابق با بدافزار رجین در سیستم شما یافت شد. \n در صورت نیاز به راهنمایی با متخصصان شرکت پیشگامان متن باز تماس بگیرید\n regin@syscare.ir',u'هشدار')
        else:
            self.AlertEvent(u'هیچ فایلی منطبق بر رجین پیدا نشد. برای اطلاعات بیشتر می توانید با متخصصان شرکت پیشگامان گسترش متن‌باز تماس بگیرید.\n regin@syscare.ir',u'پایان عملیات')

    def closeEvent(self, event):       
        st=u'آیا قصد خروج از برنامه را دارید؟'
        reply = QtGui.QMessageBox.question(self, u'هشدار',
            st, QtGui.QMessageBox.Yes | 
            QtGui.QMessageBox.No, QtGui.QMessageBox.No)
        if reply == QtGui.QMessageBox.Yes:
            event.accept()
        else:
            event.ignore() 
    
    def AlertEvent(self, st, title):       
        reply = QtGui.QMessageBox.information(self, title,
            st, QtGui.QMessageBox.Yes)

    def WarningEvent(self, st, title):       
        reply = QtGui.QMessageBox.warning(self, title,
            st, QtGui.QMessageBox.Yes)

    def ErrorEvent(self, st, title):       
        reply = QtGui.QMessageBox.critical(self, title,
            st, QtGui.QMessageBox.Yes)

    def center(self):       
        qr = self.frameGeometry()
        cp = QtGui.QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())            

def sha256(filePath):
    try:
        with open(filePath, 'rb') as file:
            file_data = file.read()
        return hashlib.sha256(file_data).hexdigest()
    except Exception, e:
        print e
        return 0
                    
def walkError(err):
    print err

if __name__ == "__main__":
  app = QtGui.QApplication(sys.argv)
  MainWindow = frmMain()
  MainWindow.show()
  sys.exit(app.exec_())

