#-*- coding: utf-8 -*-

import re
import getopt
import sys
import time
from PyQt4 import QtGui,QtCore
from gui import *
    
class frmMain(QtGui.QMainWindow):
    def __init__(self, parent=None):
        QtGui.QWidget.__init__(self, parent)
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.center()
        self.ui.RunScanner.clicked[bool].connect(self.run_scanner)
        self.ui.scan_progressBar.setMinimum(0)
        self.ui.scan_progressBar.setMaximum(100)
#         self.ui.fix_dashes.stateChanged.connect(self.fix_dashes)
#         self.ui.fix_three_dots.stateChanged.connect(self.fix_three_dots)
#         self.ui.fix_english_quotes.stateChanged.connect(self.fix_english_quotes)
#         self.ui.fix_hamzeh.clicked[bool].connect(self.fix_hamzeh)
#         self.ui.hamzeh_with_yeh.clicked[bool].connect(self.hamzeh_with_yeh)
#         self.ui.cleanup_zwnj.stateChanged.connect(self.cleanup_zwnj)
#         self.ui.fix_spacing_for_braces_and_quotes.stateChanged.connect(self.fix_spacing_for_braces_and_quotes)
#         self.ui.fix_LTRM_RTLM.stateChanged.connect(self.fix_LTRM_RTLM)
#         self.ui.fix_arabic_numbers.stateChanged.connect(self.fix_arabic_numbers)
#         self.ui.fix_english_numbers.stateChanged.connect(self.fix_english_numbers)
#         self.ui.fix_misc_non_persian_chars.stateChanged.connect(self.fix_misc_non_persian_chars)
#         self.ui.fix_perfix_spacing.stateChanged.connect(self.fix_perfix_spacing)
#         self.ui.fix_suffix_spacing.stateChanged.connect(self.fix_suffix_spacing)
# #        self.ui.aggresive.stateChanged.connect(self.aggresive)
#         self.ui.cleanup_kashidas.stateChanged.connect(self.cleanup_kashidas)
#         self.ui.cleanup_extra_marks_2.stateChanged.connect(self.cleanup_extra_marks)
#         self.ui.cleanup_spacing.stateChanged.connect(self.cleanup_spacing)
#         self.ui.AboutPush.clicked[bool].connect(self.AboutUs)

       
    def run_scanner(self, pressed):
        for item in range(0,100):
            time.sleep(0.05)
            value = self.ui.scan_progressBar.value() + 1
            self.ui.scan_progressBar.setValue(value)

    def closeEvent(self, event):       
        st=u'آیا قصد خروج از برنامه را دارید؟'
        reply = QtGui.QMessageBox.question(self, u'هشدار',
            st, QtGui.QMessageBox.Yes | 
            QtGui.QMessageBox.No, QtGui.QMessageBox.No)
        if reply == QtGui.QMessageBox.Yes:
            event.accept()
        else:
            event.ignore() 

    def center(self):       
        qr = self.frameGeometry()
        cp = QtGui.QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())            

        
    def RunlolaRun(self, pressed):
        for line in self.GetText().split('\n'):
            if len(line) == 0:
                continue
            st = (unicode(line.toUtf8(), "utf-8"))  
            run_PE.text = unicode(st)
            globals()["text2"]=globals()["text2"]+unicode(run_PE.cleanup())+"\n"
        self.ui.textEdit.setText(globals()["text2"])
        globals()["text2"]=""
 
if __name__ == "__main__":
  app = QtGui.QApplication(sys.argv)
  MainWindow = frmMain()
  MainWindow.show()
  sys.exit(app.exec_())

